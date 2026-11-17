import json
import socket
import threading

import pytest

import guard_popup


@pytest.fixture
def launcher(monkeypatch, tmp_path):
    """A socket standing in for the launcher: records each request and
    answers with what's in .answer."""
    path = str(tmp_path / "popup.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(4)
    monkeypatch.setenv(guard_popup.ENV, path)

    class Launcher:
        answer = b"no"
        requests = []

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                data = b""
                while chunk := conn.recv(4096):
                    data += chunk
                Launcher.requests.append(json.loads(data))
                conn.sendall(Launcher.answer)

    threading.Thread(target=serve, daemon=True).start()
    yield Launcher
    server.close()


# -- ask --------------------------------------------------------


def test_no_socket_means_no(monkeypatch):
    monkeypatch.delenv(guard_popup.ENV, raising=False)
    assert guard_popup.ask("guard", "text") is None


def test_socket_gone_means_no(monkeypatch, tmp_path):
    monkeypatch.setenv(guard_popup.ENV, str(tmp_path / "missing.sock"))
    assert guard_popup.ask("guard", "text") is None


@pytest.mark.parametrize(
    "sent, answer",
    [
        (b"once", "once"),
        (b"always", "always"),
        (b"no", None),
        (b"", None),
        (b"garbage", None),
        (b"once" * 100, None),
    ],
)
def test_launcher_decides_the_answer(launcher, sent, answer):
    launcher.answer = sent
    assert guard_popup.ask("guard", "text") == answer


def test_request_carries_name_and_text(launcher):
    guard_popup.ask("gh-api-proxy", "$(touch pwned)\n\x1b[2J")
    assert launcher.requests[-1] == {
        "name": "gh-api-proxy",
        "text": "$(touch pwned)\n\x1b[2J",
    }


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
