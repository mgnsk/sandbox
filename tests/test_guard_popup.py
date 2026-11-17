import os
import subprocess
import tempfile
import threading

import pytest

import guard_popup

REAL_POPEN = subprocess.Popen


class FakePopup:
    def __init__(self, returncode=0):
        self.returncode = returncode

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def wait(self):
        return self.returncode


@pytest.fixture
def created(monkeypatch, tmp_path):
    """The temp files ask() makes: the marker, then the text."""
    real_mkstemp = tempfile.mkstemp
    paths = []

    def fake_mkstemp(prefix):
        fd, path = real_mkstemp(prefix=prefix, dir=str(tmp_path))
        paths.append(path)
        return fd, path

    monkeypatch.setattr(guard_popup.tempfile, "mkstemp", fake_mkstemp)
    return paths


@pytest.fixture
def tmux(monkeypatch):
    monkeypatch.setenv("TMUX", "session")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: None)


# -- ask --------------------------------------------------------


def test_no_tmux_skips_the_popup(monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("popup shown"))
    assert guard_popup.ask("guard", "text", "cat {}", 76) is None


@pytest.mark.parametrize(
    "written, answer",
    [("once\n", "once"), ("always\n", "always"), ("", None), ("garbage\n", None)],
)
def test_marker_decides_the_answer_and_temp_files_go(monkeypatch, created, tmux, written, answer):
    def fake_popen(_cmd):
        with open(created[0], "w", encoding="utf-8") as f:
            f.write(written)
        return FakePopup()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    assert guard_popup.ask("guard", "text", "cat {}", 76) == answer
    assert not os.path.exists(created[0])
    assert not os.path.exists(created[1])


def test_popup_failing_to_launch_is_no(monkeypatch, created, tmux):
    monkeypatch.setattr(subprocess, "Popen", lambda _cmd: FakePopup(returncode=1))
    assert guard_popup.ask("guard", "text", "cat {}", 76) is None


def test_text_stays_out_of_the_popup_command(monkeypatch, created, tmux):
    """That command runs in a shell on the host."""
    commands = []
    seen_text = []

    def fake_popen(argv):
        commands.append(argv)
        with open(created[1], encoding="utf-8") as f:
            seen_text.append(f.read())
        return FakePopup()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    guard_popup.ask("guard", "$(touch pwned)", "cat {}", 76)

    assert seen_text == ["$(touch pwned)"]
    assert "pwned" not in commands[0][-1]


def test_popup_size_and_prompt(monkeypatch, created, tmux):
    commands = []

    def fake_popen(argv):
        commands.append(argv)
        return FakePopup()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    guard_popup.ask("guard", "text", "less {}", "90%", "80%")

    assert commands[0][:7] == ["tmux", "display-popup", "-E", "-w", "90%", "-h", "80%"]
    assert "A = always in this sandbox" in commands[0][-1]


@pytest.mark.parametrize(
    "typed, answer",
    [("y", "once"), ("Y", "once"), ("a", "always"), ("A", "always"), ("", None), ("n", None), ("yes", None)],
)
def test_typed_answer_through_a_real_shell(monkeypatch, created, tmux, typed, answer):
    """Runs the popup's command for real, with `tmux` shadowed by a no-op."""

    def fake_popen(argv):
        popup_cmd = "tmux() { :; }; " + argv[-1]
        with REAL_POPEN(
            ["bash", "-c", popup_cmd], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True
        ) as shell:
            shell.communicate(typed + "\n")
        return FakePopup(shell.returncode)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    assert guard_popup.ask("guard", "text", "cat {}", 76) == answer


# -- Approvals --------------------------------------------------------


def test_always_sticks():
    approvals = guard_popup.Approvals()
    assert approvals.approve(lambda: "always") is True
    assert approvals.approve(lambda: pytest.fail("asked again")) is True


@pytest.mark.parametrize("answer, allowed", [("once", True), (None, False)])
def test_other_answers_ask_again(answer, allowed):
    approvals = guard_popup.Approvals()
    asked = []

    def ask_user():
        asked.append(True)
        return answer

    assert approvals.approve(ask_user) is allowed
    assert approvals.approve(ask_user) is allowed
    assert len(asked) == 2


def test_a_new_instance_asks_again():
    """What a new sandbox gets, since each starts its own guards."""
    guard_popup.Approvals().approve(lambda: "always")
    asked = []
    guard_popup.Approvals().approve(lambda: asked.append(True))
    assert asked == [True]


def test_requests_queued_behind_always_skip_their_popup():
    approvals = guard_popup.Approvals()
    popup_up, answer_now = threading.Event(), threading.Event()
    asked, results = [], []

    def ask_user():
        asked.append(True)
        popup_up.set()
        answer_now.wait(timeout=5)
        return "always"

    def request():
        results.append(approvals.approve(ask_user))

    threads = [threading.Thread(target=request) for _ in range(4)]
    threads[0].start()
    assert popup_up.wait(timeout=5)
    for thread in threads[1:]:
        thread.start()
    answer_now.set()
    for thread in threads:
        thread.join(timeout=5)

    assert results == [True] * 4
    assert asked == [True]
