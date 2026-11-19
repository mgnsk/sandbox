"""Black-box tests for the launcher's terminal (internal/popuprelay): the
launcher runs on a pty, with a program inside that echoes what it's typed,
and popups are asked for on its guards' socket the way a guard does. What
the user sees is read off a terminal emulator (pyte) fed the launcher's
output; what the sandbox sees, off what the program inside prints."""

import json
import socket
import subprocess
import sys
import threading
import time

import pyte
import pytest
from launcher import Launcher

PROMPT = "y = once, A = always in this sandbox, N = no:"
GRACE = 0.6  # Keys typed sooner after a popup appears are dropped.

INSIDE = r"""
import os, signal, sys, time

def size(*_):
    s = os.get_terminal_size()
    print(f"size {s.lines} {s.columns}", flush=True)

signal.signal(signal.SIGWINCH, size)
print("ready", flush=True)
for line in sys.stdin:
    line = line.strip()
    if line == "quit":
        sys.exit(3)
    elif line == "exit-soon":
        time.sleep(1)
        sys.exit(3)
    elif line == "alt":
        sys.stdout.write("\x1b[?1049h"); sys.stdout.flush()
    elif line == "hide":
        sys.stdout.write("\x1b[?25l"); sys.stdout.flush()
    elif line == "split-alt":
        # A mode change split across two reads.
        sys.stdout.write("\x1b[?10"); sys.stdout.flush()
        time.sleep(0.3)
        sys.stdout.write("49h"); sys.stdout.flush()
    elif line == "reset":
        sys.stdout.write("\x1bc"); sys.stdout.flush()
    elif line.startswith("later "):
        path = line.split(" ", 1)[1]
        while not os.path.exists(path):
            time.sleep(0.05)
        print("late-output", flush=True)
    print("got:" + line, flush=True)
"""


class Session:
    """The launcher on a terminal, with INSIDE inside."""

    def __init__(self, launcher):
        launcher.config["guards"]["openUrl"] = True  # A guard, to ask through.
        script = launcher.tmp / "inside.py"
        script.write_text(INSIDE)
        self.p = launcher.pty(sys.executable, str(script))
        self.screen = pyte.Screen(80, 24)
        self.p.watchers.append(pyte.ByteStream(self.screen).feed)
        self.sock = self.p.popup_socket()
        self.p.expect("ready")

    @property
    def text(self):
        return "\n".join(line.rstrip() for line in self.screen.display)

    def shown(self, text, timeout=20):
        self.p.until(lambda: text in self.text, timeout, f"{text!r} on screen")

    def closed(self, start):
        """Wait for the popup screen to close (pyte has no alternate screen
        to see it on)."""
        self.p.until(lambda: b"\x1b[?1049l" in self.p.raw[start:], what="popup closed")

    def ask(self, text, name="test-guard", raw=None):
        """Ask in the background, as a guard does; the list the answer
        ("" for none) lands in."""
        answers = []

        def run():
            with socket.socket(socket.AF_UNIX) as sock:
                sock.connect(self.sock)
                sock.sendall(
                    raw
                    if raw is not None
                    else json.dumps({"name": name, "text": text}).encode()
                )
                sock.shutdown(socket.SHUT_WR)
                answer = b""
                try:
                    while chunk := sock.recv(64):
                        answer += chunk
                except OSError:
                    pass
                answers.append(answer.decode())

        threading.Thread(target=run, daemon=True).start()
        return answers

    def answered(self, answers, timeout=10):
        deadline = time.monotonic() + timeout
        while not answers:
            assert time.monotonic() < deadline, "no answer"
            self.p.read_for(0.05)
        return answers[0]

    def type(self, keys):
        self.p.send(keys)

    def answer(self, keys):
        """Answer the popup on screen, once keys count."""
        self.p.read_for(GRACE)
        self.type(keys)

    def quit(self):
        self.type("quit\r")
        return self.p.wait()


@pytest.fixture
def session(tmp_path):
    launcher = Launcher(tmp_path)
    s = Session(launcher)
    yield s
    if s.p.proc.poll() is None:
        # Forwarded to the sandbox, which ends it all as a closed terminal would.
        s.p.signal()
        try:
            s.p.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            s.p.proc.kill()
    launcher.close()


# -- relaying ---------------------------------------------------------------------


def test_relays_both_ways_and_the_exit_status(session):
    session.type("hello\r")
    session.p.expect("got:hello")
    assert session.quit().returncode == 3


def test_resizing_reaches_the_sandbox(session):
    session.p.resize(30, 100)
    session.p.expect("size 30 100")


# -- a popup ----------------------------------------------------------------------


def test_popup_takes_the_keys_and_the_sandbox_never_sees_them(session):
    session.type("before\r")
    session.p.expect("got:before")
    start = len(session.p.raw)
    answers = session.ask("Allow the thing?")
    session.shown("Allow the thing?")
    # On the alternate screen, over the sandbox's.
    assert b"\x1b[?1049h" in session.p.raw[start:]
    # Within the grace period: dropped, not answered, not relayed.
    session.type("y\r")
    session.answer("a\r")
    assert session.answered(answers) == "always"
    session.closed(start)

    session.type("after\r")
    session.p.expect("got:after")
    assert session.quit().returncode == 3
    assert b"got:y\r" not in session.p.raw and b"got:a\r" not in session.p.raw


def test_screen_shows_who_asks_the_text_and_the_prompt(session):
    session.ask(
        "Open in the host's browser?\n\n  host:     example.com\n",
        name="open-url-guard",
    )
    session.shown(PROMPT)
    lines = session.screen.display
    assert lines[0].startswith(" sandbox: open-url-guard asks for approval")
    assert lines[1].rstrip() == "Open in the host's browser?"
    assert lines[3].rstrip() == "  host:     example.com"
    assert lines[23].startswith(PROMPT)


TYPED = [
    ("y\r", "once"),
    ("Y\r", "once"),
    ("a\r", "always"),
    ("A\r", "always"),
    ("\r", "no"),
    ("n\r", "no"),
    ("yes\r", "no"),
    ("\x03", "no"),
    ("\x04", "no"),
    ("x\x7fy\r", "once"),
    ("x\x08y\r", "once"),
    ("a\x15\r", "no"),
    ("y\n", "once"),
]


def test_typed_answers(session):
    for keys, answer in TYPED:
        answers = session.ask(f"question {keys!r}")
        session.shown(f"question {keys!r}")
        session.answer(keys)
        assert session.answered(answers) == answer, keys


def test_no_answer_until_enter_and_what_is_typed_shows(session):
    answers = session.ask("question")
    session.shown(PROMPT)
    session.answer("y")
    session.shown(PROMPT + " y")
    session.p.read_for(0.3)
    assert answers == []
    session.type("\r")
    assert session.answered(answers) == "once"


def test_keys_during_grace_are_dropped(session):
    answers = session.ask("question")
    session.shown(PROMPT)
    session.type("y\r")
    session.p.read_for(0.2)
    assert answers == []
    session.answer("\r")
    assert session.answered(answers) == "no"


def test_popups_queue_one_at_a_time(session):
    start = len(session.p.raw)
    first = session.ask("first request")
    session.shown("first request")
    second = session.ask("second request")
    session.p.read_for(0.4)
    assert "second request" not in session.text
    session.answer("y\r")
    assert session.answered(first) == "once"
    session.shown("second request")
    session.answer("\r")
    assert session.answered(second) == "no"
    # One screen for both.
    session.closed(start)
    assert session.p.raw[start:].count(b"\x1b[?1049h") == 1


def test_sandbox_exiting_under_a_popup_answers_no(session):
    session.type("exit-soon\r")
    answers = session.ask("pending")
    session.shown("pending")
    assert session.answered(answers) == "no"
    assert session.p.wait().returncode == 3


def test_hanging_up_under_a_popup_answers_no(session):
    answers = session.ask("pending")
    session.shown("pending")
    session.p.hang_up()
    deadline = time.monotonic() + 10
    while not answers:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert answers == ["no"]


def test_output_is_held_back_under_a_popup(session, tmp_path):
    flag = tmp_path / "flag"
    session.type(f"later {flag}\r")
    answers = session.ask("question")
    session.shown("question")
    flag.touch()
    session.p.read_for(0.5)
    assert b"late-output" not in session.p.raw
    session.answer("y\r")
    session.answered(answers)
    session.shown("late-output")


def test_malformed_requests_are_dropped(session):
    for raw in (
        b"not json",
        b"{}",
        json.dumps({"name": "x"}).encode(),
        b"x" * (1 << 20 | 1),
    ):
        assert session.answered(session.ask(None, raw=raw)) == ""
    assert PROMPT not in session.text
    answers = session.ask("still works")
    session.shown("still works")
    session.answer("y\r")
    assert session.answered(answers) == "once"


# -- what's drawn -----------------------------------------------------------------


def test_long_text_scrolls(session):
    session.ask("\n".join(f"line{i}" for i in range(30)))
    session.shown(PROMPT)

    def status():
        return session.screen.display[22]

    assert "lines 1-21 of 30 - Up/Down/PgUp/PgDn to read it all" in status()
    assert session.screen.display[1].rstrip() == "line0"
    assert "line21" not in session.text
    session.answer("\x1b[B\x1b[B\x1bOB")
    session.shown("lines 4-24 of 30")
    assert session.screen.display[1].rstrip() == "line3"
    session.type("\x1b[6~\x1b[6~")
    session.shown("lines 10-30 of 30")
    session.type("\x1b[H")
    session.shown("lines 1-21 of 30")
    session.type("\x1b[F")
    session.shown("lines 10-30 of 30")
    session.type("\x1b[5~\x1b[A")
    session.shown("lines 1-21 of 30")
    # Scrolling never types.
    assert session.screen.display[23].rstrip() == PROMPT


def test_text_is_wrapped_not_cut(session):
    session.ask("x" * 100 + "\n" + "界" * 50)
    session.shown(PROMPT)
    lines = [line.rstrip() for line in session.screen.display]
    assert lines[1:3] == ["x" * 80, "x" * 20]
    # Wide characters count double; pyte shows each as itself plus "".
    assert lines[3].replace(" ", "") == "界" * 40
    assert lines[4].replace(" ", "") == "界" * 10


def test_trailing_blank_lines_go(session):
    session.ask("a\n\nb" + "\n" * 40)
    session.shown(PROMPT)
    assert "lines " not in session.text  # Nothing to scroll to.


def test_escapes_and_bidi_are_neutralised(session):
    start = len(session.p.raw)
    session.ask("a\x1b[2Jb‮c\rd\tz\n\x1b]52;c;aGk=\x07", name="evil\x1b[31m")
    session.shown(PROMPT)
    assert "a?[2Jb?c?d    z" in session.text
    assert "sandbox: evil?[31m asks for approval" in session.text
    shown = session.p.raw[start:]
    assert b"\x1b]" not in shown and b"\x07" not in shown
    assert b"\x1b[31m" not in shown


def test_a_resize_redraws_the_popup_and_reaches_the_sandbox_after(session):
    answers = session.ask("\n".join(f"line{i}" for i in range(30)))
    session.shown("lines 1-21 of 30")
    session.p.resize(40, 100)
    session.screen.resize(40, 100)
    session.p.until(lambda: "lines 1-21" not in session.text, what="redrawn")
    assert "line29" in session.text
    session.answer("y\r")
    session.answered(answers)
    session.p.expect("size 40 100")


# -- the sandbox's own screen -------------------------------------------------------


@pytest.mark.parametrize("enter", ["alt", "split-alt"])
def test_over_a_full_screen_program_it_is_told_to_redraw(session, enter):
    """On the alternate screen already (vim, less), the popup is drawn there,
    and a resize away and back has the program redraw."""
    session.type(f"{enter}\r")
    session.p.expect(f"got:{enter}")
    start = len(session.p.raw)
    answers = session.ask("question")
    session.shown("question")
    assert b"\x1b[?1049h" not in session.p.raw[start:]
    assert b"\x1b7" in session.p.raw[start:]
    session.answer("y\r")
    session.answered(answers)
    session.p.expect("size 24 79")
    session.p.expect("size 24 80")
    assert b"\x1b8" in session.p.raw[start:]


def test_the_cursor_is_left_as_the_sandbox_had_it(session):
    session.type("hide\r")
    session.p.expect("got:hide")
    answers = session.ask("question")
    session.shown("question")
    session.answer("y\r")
    session.answered(answers)
    session.p.until(lambda: session.screen.cursor.hidden, what="cursor hidden")
    # A terminal reset brings it back, and the main screen.
    session.type("alt\r")
    session.p.expect("got:alt")
    session.type("reset\r")
    session.p.expect("got:reset")
    start = len(session.p.raw)
    answers = session.ask("again")
    session.shown("again")
    assert b"\x1b[?1049h" in session.p.raw[start:]
    session.answer("y\r")
    session.answered(answers)
    session.p.until(lambda: not session.screen.cursor.hidden, what="cursor shown")
