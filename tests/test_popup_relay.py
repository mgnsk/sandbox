import os
import select
import subprocess
import sys
import threading
import time

import pytest
from conftest import BIN_DIR

import guard_popup
import popup_relay

# -- text ------------------------------------------------------------------------


def test_escapes_and_bidi_are_neutralised():
    lines = popup_relay.wrap("a\x1b[2Jb‮c\rd", 80)
    assert lines == ["a?[2Jb?c?d"]


def test_long_lines_wrap_rather_than_cut():
    assert popup_relay.wrap("x" * 25, 10) == ["x" * 10, "x" * 10, "x" * 5]


def test_wide_chars_count_double():
    assert popup_relay.wrap("界" * 6, 10) == ["界" * 5, "界"]


def test_trailing_blank_lines_go():
    assert popup_relay.wrap("a\n\nb\n\n", 10) == ["a", "", "b"]


# -- Popup -------------------------------------------------------------------


def popup(text="text", rows=10, cols=40, grace=0.0):
    return popup_relay.Popup("guard", text, rows, cols, now=0.0, grace=grace)


@pytest.mark.parametrize(
    "typed, answer",
    [
        (b"y\r", "once"),
        (b"Y\r", "once"),
        (b"a\r", "always"),
        (b"A\r", "always"),
        (b"\r", "no"),
        (b"n\r", "no"),
        (b"yes\r", "no"),
        (b"\x03", "no"),
        (b"x\x7fy\r", "once"),
        (b"a\x15\r", "no"),
    ],
)
def test_typed_answer(typed, answer):
    assert popup().feed(typed, now=1.0) == answer


def test_no_answer_until_enter():
    p = popup()
    assert p.feed(b"y", now=1.0) is None
    assert p.feed(b"\r", now=1.0) == "once"


def test_keys_during_grace_are_dropped():
    p = popup(grace=0.5)
    assert p.feed(b"y\r", now=0.1) is None
    assert p.typed == ""
    assert p.feed(b"\r", now=0.6) == "no"


def test_arrow_keys_scroll_instead_of_typing():
    p = popup("\n".join(str(i) for i in range(30)), rows=10)
    p.feed(b"\x1b[B\x1b[B\x1bOB", now=1.0)
    assert p.top == 3 and p.typed == ""
    p.feed(b"\x1b[6~\x1b[6~\x1b[6~\x1b[6~", now=1.0)
    assert p.top == p.max_top() == 30 - 7
    p.feed(b"\x1b[H", now=1.0)
    assert p.top == 0


def test_render_shows_the_text_and_where_more_is():
    p = popup("\n".join(f"line{i}" for i in range(30)), rows=10, cols=80)
    screen = p.render(now=1.0).decode()
    assert "guard asks for approval" in screen
    assert "line0" in screen and "line6" in screen and "line7" not in screen
    assert "lines 1-7 of 30" in screen
    assert popup_relay.PROMPT.strip() in screen


def test_render_never_passes_escapes_from_the_text():
    screen = popup("\x1b]52;c;aGk=\x07\x1b[2J").render(now=1.0)
    assert b"\x1b]" not in screen
    assert b"\x07" not in screen


# -- Modes -------------------------------------------------------------------


def test_modes_follow_alt_screen_and_cursor():
    m = popup_relay.Modes()
    m.feed(b"\x1b[?1049h\x1b[?25l")
    assert m.alt and not m.cursor
    m.feed(b"xx\x1b[?10")
    m.feed(b"49l")
    assert not m.alt
    m.feed(b"\x1bc")
    assert m.cursor


# -- the relay, on a real pty -------------------------------------------------

DRIVER = """
import sys
sys.path.insert(0, sys.argv[1])
import popup_relay
listener = popup_relay.listen(sys.argv[2])
sys.exit(popup_relay.Relay(listener, grace=float(sys.argv[3])).run(sys.argv[4:]))
"""

CHILD = """
import sys
for line in sys.stdin:
    line = line.strip()
    if line == "quit":
        sys.exit(3)
    print("got:" + line, flush=True)
"""


class Terminal:
    """The test's end of a pty the relay runs on, as if a user's terminal."""

    def __init__(self, master):
        self.master = master
        self.seen = b""

    def type(self, data):
        os.write(self.master, data)

    def wait_for(self, text, timeout=10):
        deadline = time.monotonic() + timeout
        while text not in self.seen:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AssertionError(f"{text!r} never shown; saw {self.seen!r}")
            if select.select([self.master], [], [], left)[0]:
                try:
                    self.seen += os.read(self.master, 65536)
                except OSError:
                    raise AssertionError(
                        f"{text!r} never shown; saw {self.seen!r}"
                    ) from None


@pytest.fixture
def relay(tmp_path, monkeypatch):
    master, slave = os.openpty()
    popup_relay.set_size(slave, (24, 80, 0, 0))
    sock = str(tmp_path / "popup.sock")
    proc = subprocess.Popen(
        [sys.executable, "-c", DRIVER, str(BIN_DIR), sock, "0.3",
         sys.executable, "-c", CHILD],
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
    )  # fmt: skip
    os.close(slave)
    deadline = time.monotonic() + 10
    while not os.path.exists(sock):
        assert proc.poll() is None and time.monotonic() < deadline
        time.sleep(0.02)
    monkeypatch.setenv(guard_popup.ENV, sock)
    yield Terminal(master), proc
    if proc.poll() is None:
        proc.kill()
    proc.wait()
    os.close(master)


def ask_in_background(text):
    answers = []
    thread = threading.Thread(
        target=lambda: answers.append(guard_popup.ask("test-guard", text))
    )
    thread.start()
    return thread, answers


def test_relays_both_ways_and_the_exit_status(relay):
    term, proc = relay
    term.type(b"hello\r")
    term.wait_for(b"got:hello")
    term.type(b"quit\r")
    assert proc.wait(timeout=10) == 3


def test_popup_takes_the_keys_and_the_sandbox_never_sees_them(relay):
    term, proc = relay
    term.type(b"before\r")
    term.wait_for(b"got:before")

    thread, answers = ask_in_background("Allow the thing?")
    term.wait_for(b"Allow the thing?")
    assert b"\x1b[?1049h" in term.seen
    # Within the grace period: dropped, not answered, not relayed.
    term.type(b"y\r")
    time.sleep(0.5)
    term.type(b"a\r")
    thread.join(timeout=10)
    assert answers == ["always"]
    term.wait_for(b"\x1b[?1049l")

    term.type(b"after\r")
    term.wait_for(b"got:after")
    term.type(b"quit\r")
    assert proc.wait(timeout=10) == 3
    assert b"got:y" not in term.seen and b"got:a\r" not in term.seen


def test_popups_queue_one_at_a_time(relay):
    term, _ = relay
    first, first_answer = ask_in_background("first request")
    term.wait_for(b"first request")
    second, second_answer = ask_in_background("second request")
    time.sleep(0.4)
    assert b"second request" not in term.seen
    term.type(b"y\r")
    first.join(timeout=10)
    term.wait_for(b"second request")
    time.sleep(0.4)
    term.type(b"\r")
    second.join(timeout=10)
    assert (first_answer, second_answer) == (["once"], [None])


def test_sandbox_exiting_under_a_popup_answers_no(relay):
    term, proc = relay
    thread, answers = ask_in_background("pending")
    term.wait_for(b"pending")
    proc.terminate()
    thread.join(timeout=10)
    assert answers == [None]
