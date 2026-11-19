"""Black-box tests for open-url-guard, run as a program with a stand-in
for the host's xdg-open on its PATH, and for sandbox-xdg-open, the
client inside."""

import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest
from guards import FakePopups, Guard, base_env, guard_argv, short_dir

XDG_OPEN = """#!{python}
import json, os, sys
with open({log!r}, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
"""


@pytest.fixture
def world():
    d = short_dir()
    popups = FakePopups(d / "popup.sock")
    bin_dir = d / "bin"
    bin_dir.mkdir()
    log = d / "opened.log"
    (bin_dir / "xdg-open").write_text(
        XDG_OPEN.format(python=sys.executable, log=str(log))
    )
    (bin_dir / "xdg-open").chmod(0o755)
    guards = []

    def start(popup=True, xdg_open=True):
        sock = d / f"open-url{len(guards)}.sock"
        env = base_env(
            PATH=str(bin_dir) if xdg_open else "/nonexistent",
            SANDBOX_POPUP_SOCKET=popups.path if popup else None,
        )
        guards.append(Guard("open-url-guard", sock, env=env, ready=sock))
        return str(sock)

    def opened(expect=0):
        """The URLs xdg-open got, waiting for expect of them: it's started
        in the background, so a browser can outlive the guard."""
        deadline = time.monotonic() + 10
        while True:
            urls = (
                [json.loads(line) for line in log.read_text().splitlines()]
                if log.exists()
                else []
            )
            if len(urls) >= expect or time.monotonic() > deadline:
                return urls
            time.sleep(0.05)

    yield start, popups, opened
    for guard in guards:
        guard.stop()
    popups.close()


def ask(path, data):
    """Send data as a client does; the guard's reply."""
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(path)
        sock.settimeout(10)
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        reply = b""
        while chunk := sock.recv(4096):
            reply += chunk
        return reply.decode()


@pytest.fixture
def guard(world):
    start, popups, opened = world
    return start(), popups, opened


# -- which URLs ----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/a/b?c=d&e=%20f#g",
        "HTTPS://example.com",
        "http://localhost:5173/",
        "http://127.0.0.1:8080",
        "http://[::1]:8080/",
        "http://[fe80::1%25eth0]/",
        "http://[v1.fe]/",
        "HtTp://example.com",
    ],
)
def test_web_urls_are_offered_and_opened(guard, url):
    path, popups, opened = guard
    popups.answer = b"once"
    assert ask(path, url.encode() + b"\n") == "ok\n"
    assert opened(1) == [[url]]
    [asked] = popups.requests
    assert asked["name"] == "open-url-guard"


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
        "https://exa\tmple.com",
        "https://example.com/\x1b[2J",
        "https://example.com/\x7f",
        "https://exаmple.com",  # Cyrillic а
        "https://github.com@evil.example",
        "https://user:pass@example.com",
        "https://github.com\\.evil.example",
        "https://[::1",
        "https://::1]/",
        "https://a]b[/",
        "https://a[::1]/",
        "https://[::1]x/",
        "https://[1.2.3.4]/",
        "https://[vz]/",
        "https://[nonsense]/",
        "h-t+t.p://example.com",
        "http:example.com",
    ],
)
def test_everything_else_is_refused_without_asking(guard, url):
    path, popups, opened = guard
    popups.answer = b"always"
    reply = ask(path, url.encode() + b"\n")
    assert reply.startswith("denied: ") and reply.endswith("\n")
    assert popups.requests == []
    assert opened() == []


def test_only_the_first_line_counts(guard):
    path, popups, opened = guard
    popups.answer = b"once"
    assert ask(path, b"https://example.com\nfile:///etc/passwd\n") == "ok\n"
    assert opened(1) == [["https://example.com"]]


def test_a_url_without_a_newline_is_read_to_the_end(guard):
    path, popups, opened = guard
    popups.answer = b"once"
    assert ask(path, b"https://example.com/x") == "ok\n"
    assert opened(1) == [["https://example.com/x"]]


def test_oversized_input_is_refused(guard):
    path, popups, _ = guard
    popups.answer = b"always"
    # 4097 bytes: all of them read, so the reply isn't lost to a reset.
    assert (
        ask(path, b"https://example.com/" + b"a" * 4077)
        == "denied: URL too long or not UTF-8\n"
    )
    # Longer: refused all the same, the reply perhaps lost to a reset.
    try:
        reply = ask(path, b"https://example.com/" + b"a" * 100000 + b"\n")
    except ConnectionResetError:
        reply = None
    assert reply in (None, "denied: URL too long or not UTF-8\n")
    assert popups.requests == []


def test_undecodable_input_is_refused(guard):
    path, popups, _ = guard
    popups.answer = b"always"
    assert (
        ask(path, b"https://example.com/\xff\n")
        == "denied: URL too long or not UTF-8\n"
    )
    assert popups.requests == []


# -- the popup ------------------------------------------------------------------


def test_declined_url_is_not_opened(guard):
    path, popups, opened = guard
    assert ask(path, b"https://example.com\n") == "denied: not approved\n"
    assert len(popups.requests) == 1
    assert opened() == []


def test_popup_shows_host_url_and_requester(guard, tmp_path):
    path, popups, _ = guard
    client = tmp_path / "client.py"
    client.write_text(
        "import socket, sys\n"
        "s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[2])\n"
        "s.sendall(b'https://example.com/x\\n'); s.recv(64)\n"
    )
    subprocess.run(
        [sys.executable, client, "marker\x1b[2J", path], cwd=tmp_path, check=True
    )
    [text] = popups.texts
    assert text.startswith("Open in the host's browser?\n\n")
    assert "  host:     example.com\n" in text
    assert f"  cwd:      {tmp_path}\n" in text
    assert "marker?[2J" in text and "\x1b" not in text
    # Whole, not truncated: a URL is approved for exactly what's on screen.
    assert "\nhttps://example.com/x\n" in text


def test_long_urls_are_shown_whole(guard):
    path, popups, _ = guard
    url = "https://example.com/" + "a" * 3000
    ask(path, url.encode() + b"\n")
    assert url in popups.texts[0]


def test_always_stops_asking_for_this_guard_but_not_the_next(world):
    start, popups, opened = world
    path = start()
    popups.answer = b"always"
    assert ask(path, b"https://example.com\n") == "ok\n"
    popups.answer = b"no"
    assert ask(path, b"https://other.example\n") == "ok\n"
    # It doesn't cover an invalid URL.
    assert ask(path, b"file:///etc/passwd\n").startswith("denied:")
    assert len(popups.requests) == 1
    assert sorted(opened(2)) == [["https://example.com"], ["https://other.example"]]
    # A new sandbox's guard asks again.
    assert ask(start(), b"https://example.com\n") == "denied: not approved\n"
    assert len(popups.requests) == 2


@pytest.mark.parametrize(
    ("answer", "reply"),
    [
        (b"once", "ok\n"),
        (b"always", "ok\n"),
        (b"no", "denied: not approved\n"),
        (b"", "denied: not approved\n"),
        (b"garbage", "denied: not approved\n"),
        (b"once" * 100, "denied: not approved\n"),
    ],
)
def test_the_launchers_answer_decides(guard, answer, reply):
    path, popups, _ = guard
    popups.answer = answer
    assert ask(path, b"https://example.com\n") == reply


def test_without_a_popup_socket_nothing_is_opened(world):
    start, _, opened = world
    assert ask(start(popup=False), b"https://example.com\n") == "denied: not approved\n"
    assert opened() == []


def test_a_popup_socket_gone_means_no(world):
    start, popups, opened = world
    path = start()
    popups.close()
    os.unlink(popups.path)
    assert ask(path, b"https://example.com\n") == "denied: not approved\n"


def test_requests_queued_behind_always_skip_their_popup(guard):
    """One popup at a time, and requests waiting behind an "always" answer
    see it instead of popping up themselves."""
    path, popups, opened = guard
    popups.answer = b"always"
    popups.hold = threading.Event()
    replies = []
    threads = [
        threading.Thread(
            target=lambda: replies.append(ask(path, b"https://example.com\n"))
        )
        for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    time.sleep(0.5)
    assert len(popups.requests) == 1
    popups.hold.set()
    for thread in threads:
        thread.join(timeout=10)
    assert replies == ["ok\n"] * 4
    assert len(popups.requests) == 1
    assert len(opened(4)) == 4


def test_failing_to_start_xdg_open_is_reported(world):
    start, popups, _ = world
    popups.answer = b"once"
    reply = ask(start(xdg_open=False), b"https://example.com\n")
    assert reply.startswith("denied: couldn't run xdg-open: ")


# -- sandbox-xdg-open -------------------------------------------------------------


def run_shim(runtime_dir, *args):
    return subprocess.run(
        guard_argv("sandbox-xdg-open", *args),
        env={**os.environ, "XDG_RUNTIME_DIR": str(runtime_dir)},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_shim_through_the_guard(world):
    start, popups, opened = world
    path = start()
    runtime = short_dir()
    os.symlink(path, runtime / "open-url.sock")
    popups.answer = b"once"
    result = run_shim(runtime, "https://example.com")
    assert result.returncode == 0, result.stderr
    assert opened(1) == [["https://example.com"]]
    popups.answer = b"no"
    result = run_shim(runtime, "https://example.com")
    assert result.returncode == 4
    assert "xdg-open: denied: not approved" in result.stderr


def test_shim_wants_exactly_one_argument(tmp_path):
    assert run_shim(tmp_path).returncode == 1
    assert run_shim(tmp_path, "a", "b").returncode == 1


def test_shim_without_a_guard_fails(tmp_path):
    result = run_shim(tmp_path, "https://example.com")
    assert result.returncode == 4
    assert "open-url.sock" in result.stderr


def test_shim_with_a_guard_that_hangs_up(tmp_path):
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(tmp_path / "open-url.sock"))
    server.listen(1)

    def hang_up():
        conn, _ = server.accept()
        conn.recv(4096)
        conn.close()

    threading.Thread(target=hang_up, daemon=True).start()
    result = run_shim(tmp_path, "https://example.com")
    assert result.returncode == 4
    assert "no answer from open-url-guard" in result.stderr
    server.close()
