import os
import socket
import subprocess
import sys
import threading

import pytest
from conftest import BIN_DIR, load_module

open_url_guard = load_module("open-url-guard")

SHIM = BIN_DIR / "sandbox-xdg-open"


# -- validate_url --------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/a/b?c=d&e=%20f#g",
        "HTTPS://example.com",
        "http://localhost:5173/",
        "http://127.0.0.1:8080",
        "http://[::1]:8080/",
    ],
)
def test_web_urls_are_accepted(url):
    assert open_url_guard.validate_url(url) is None


@pytest.mark.parametrize(
    "url",
    [
        "",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "steam://run/1",
        "claude-cli://open",
        "/etc/passwd",
        "example.com",
        "--help",
        "-https://example.com",
        "https://",
        "https:///path",
        "https://exa mple.com",
        "https://example.com\n",
        "https://exa\tmple.com",
        "https://example.com/\x1b[2J",
        "https://example.com/\x7f",
        "https://exаmple.com",  # Cyrillic а
        "https://github.com@evil.example",
        "https://user:pass@example.com",
        "https://github.com\\.evil.example",
        "https://[::1",
    ],
)
def test_everything_else_is_refused(url):
    assert open_url_guard.validate_url(url) is not None


# -- handle_client --------------------------------------------------------


@pytest.fixture(autouse=True)
def fresh_approvals(monkeypatch):
    monkeypatch.setattr(
        open_url_guard, "APPROVALS", open_url_guard.guard_popup.Approvals()
    )


def request(data, approve="once"):
    """Run handle_client for a client sending data. Returns (reply, URLs
    confirmed, URLs opened)."""
    confirmed, opened = [], []

    def confirm(url, _cwd, _cmdline):
        confirmed.append(url)
        return approve

    client, server = socket.socketpair()
    client.sendall(data)
    client.shutdown(socket.SHUT_WR)
    open_url_guard.handle_client(server, confirm=confirm, opener=opened.append)
    reply = client.recv(4096).decode()
    client.close()
    return reply, confirmed, opened


def test_approved_url_is_opened():
    assert request(b"https://example.com\n") == (
        "ok\n",
        ["https://example.com"],
        ["https://example.com"],
    )


def test_declined_url_is_not_opened():
    reply, confirmed, opened = request(b"https://example.com\n", approve=None)
    assert reply == "denied: not approved\n"
    assert confirmed and not opened


def test_always_stops_asking_for_this_guard():
    _, confirmed, opened = request(b"https://example.com\n", approve="always")
    assert confirmed == opened == ["https://example.com"]
    reply, confirmed, opened = request(b"https://other.example\n", approve=None)
    assert reply == "ok\n"
    assert not confirmed and opened == ["https://other.example"]


def test_always_does_not_cover_an_invalid_url():
    request(b"https://example.com\n", approve="always")
    reply, _, opened = request(b"file:///etc/passwd\n")
    assert reply.startswith("denied:")
    assert not opened


def test_invalid_url_never_reaches_the_popup():
    reply, confirmed, opened = request(b"file:///etc/passwd\n")
    assert reply.startswith("denied: ")
    assert not confirmed and not opened


def test_only_the_first_line_counts():
    _, confirmed, opened = request(b"https://example.com\nfile:///etc/passwd\n")
    assert confirmed == opened == ["https://example.com"]


@pytest.mark.parametrize(
    "data",
    [
        b"https://example.com/" + b"a" * open_url_guard.MAX_URL_SIZE + b"\n",
        b"https://example.com/\xff\n",
    ],
)
def test_oversized_or_undecodable_input_is_refused(data):
    reply, confirmed, opened = request(data)
    assert reply.startswith("denied: ")
    assert not confirmed and not opened


def test_failing_to_start_xdg_open_is_reported():
    def opener(_url):
        raise FileNotFoundError(2, "No such file or directory")

    client, server = socket.socketpair()
    client.sendall(b"https://example.com\n")
    open_url_guard.handle_client(server, confirm=lambda *_: "once", opener=opener)
    assert client.recv(4096).startswith(b"denied: couldn't run")
    client.close()


# -- confirm_via_popup --------------------------------------------------------


def test_no_popup_socket_means_no(monkeypatch):
    monkeypatch.delenv("SANDBOX_POPUP_SOCKET", raising=False)
    assert open_url_guard.confirm_via_popup("https://example.com", "/", "x") is None


def test_popup_shows_host_url_and_requester(monkeypatch):
    shown = []
    monkeypatch.setattr(
        open_url_guard.guard_popup, "ask", lambda name, text: shown.append(text)
    )
    open_url_guard.confirm_via_popup("https://example.com/x", "/cwd", "cmd\x1b[2J")
    assert "example.com" in shown[0]
    assert "https://example.com/x" in shown[0]
    assert "/cwd" in shown[0]
    assert "\x1b" not in shown[0]


# -- main + sandbox-xdg-open --------------------------------------------------------


@pytest.fixture
def stub_guard(tmp_path):
    """A socket at the shim's path answering with the set reply, recording
    what it's sent."""
    runtime_dir = tmp_path / "run"
    runtime_dir.mkdir()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(runtime_dir / "open-url.sock"))
    server.listen(1)
    state = {"reply": b"ok\n", "received": None, "dir": runtime_dir}

    def serve():
        client, _ = server.accept()
        with client:
            state["received"] = client.recv(8192)
            client.sendall(state["reply"])

    state["serve"] = threading.Thread(target=serve, daemon=True)
    yield state
    server.close()


def run_shim(runtime_dir, *args):
    env = {**os.environ, "XDG_RUNTIME_DIR": str(runtime_dir)}
    return subprocess.run(
        [sys.executable, str(SHIM), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_shim_exits_zero_on_ok(stub_guard):
    stub_guard["serve"].start()
    result = run_shim(stub_guard["dir"], "https://example.com")
    assert result.returncode == 0, result.stderr
    assert stub_guard["received"] == b"https://example.com\n"


def test_shim_reports_a_denial(stub_guard):
    stub_guard["reply"] = b"denied: not approved\n"
    stub_guard["serve"].start()
    result = run_shim(stub_guard["dir"], "https://example.com")
    assert result.returncode == 4
    assert "not approved" in result.stderr


def test_shim_wants_exactly_one_argument(tmp_path):
    assert run_shim(tmp_path).returncode == 1
    assert run_shim(tmp_path, "a", "b").returncode == 1


def test_shim_without_a_guard_fails(tmp_path):
    result = run_shim(tmp_path, "https://example.com")
    assert result.returncode == 4
    assert "open-url.sock" in result.stderr
