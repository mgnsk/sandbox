"""Black-box tests for src/claude-api-proxy, run as a program: which paths it
forwards, the key swap, and streaming, with a stand-in for the Claude API.
The shared mechanics (refusals, hop-by-hop headers) are covered through
gh-api-proxy's tests."""

import http.client
import json
import socket
import time

import pytest
from guards import FakeCA, FakePopups, Guard, Upstream, base_env, short_dir

KEY = "sk-ant-api03-" + "k" * 40


@pytest.fixture
def world():
    d = short_dir()
    ca = FakeCA(d)
    upstream = Upstream(ca)
    popups = FakePopups(d / "popup.sock")
    key_file = d / "claude-api-key"
    key_file.write_text(KEY + "\n")
    guard = Guard(
        "claude-api-proxy",
        d / "api.sock",
        key_file,
        env=base_env(
            SSL_CERT_FILE=ca.file,
            SANDBOX_TEST_UPSTREAM=upstream.address,
            SANDBOX_POPUP_SOCKET=popups.path,
        ),
        ready=d / "api.sock",
    )
    yield str(d / "api.sock"), key_file, upstream, popups
    guard.stop()
    popups.close()
    upstream.close()


def connect(sock_path, method, host, path, body=b""):
    """Send a request the way Claude Code does; return the open response."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    head = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
        "Authorization: Bearer sandbox-placeholder\r\n"
        "x-api-key: sandbox-placeholder\r\n"
        "anthropic-version: 2023-06-01\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    sock.sendall(head.encode() + body)
    response = http.client.HTTPResponse(sock, method=method)
    response.begin()
    return sock, response


def request(sock_path, method, host, path, body=b""):
    sock, response = connect(sock_path, method, host, path, body)
    with sock:
        return response.status, response.read()


@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        ("/v1/messages", True),
        ("/v1/messages?beta=true", True),
        ("/v1/messages/count_tokens?beta=true", True),
        ("/v1/models", True),
        ("/v1/models/claude-opus-5-5", True),
        ("/api/claude_code/policy_limits", True),
        ("/v1/messages/batches", False),
        ("/v1/files", False),
        ("/v1/models/../files", False),
        ("/api/oauth/profile", False),
        ("/", False),
    ],
)
def test_paths(world, path, allowed):
    sock_path, _, upstream, popups = world
    status, body = request(sock_path, "POST", "api.anthropic.com", path, b"{}")
    if allowed:
        assert status == 200, body
        assert upstream.seen[0]["path"] == path
    else:
        assert status == 403
        assert "path not allowed" in json.loads(body)["message"]
        assert upstream.seen == []
    # Asks nothing: a request per turn is too many for popups.
    assert popups.requests == []


def test_messages_go_upstream_with_the_real_key_only(world):
    sock_path, _, upstream, _ = world
    status, body = request(
        sock_path, "POST", "api.anthropic.com", "/v1/messages?beta=true", b"{}"
    )

    assert status == 200 and json.loads(body)["path"] == "/v1/messages?beta=true"
    [seen] = upstream.seen
    assert seen["headers"]["Host"] == "api.anthropic.com"
    assert seen["headers"]["x-api-key"] == KEY
    assert "Authorization" not in seen["headers"]
    assert seen["headers"]["anthropic-version"] == "2023-06-01"
    assert seen["body"] == b"{}"


def test_localhost_requests_go_to_the_api(world):
    sock_path, _, upstream, _ = world
    status, _ = request(sock_path, "GET", "localhost", "/api/claude_code/policy_limits")
    assert status == 200
    assert upstream.seen[0]["headers"]["Host"] == "api.anthropic.com"


def test_other_hosts_are_refused(world):
    sock_path, _, upstream, _ = world
    status, body = request(sock_path, "POST", "example.com", "/v1/messages")
    assert status == 403 and "host not allowed" in json.loads(body)["message"]
    assert upstream.seen == []


@pytest.mark.parametrize("content", [None, "not a key\n", "x" * 10])
def test_without_a_key_it_says_how_to_set_one(world, content):
    sock_path, key_file, upstream, _ = world
    if content is None:
        key_file.unlink()
    else:
        key_file.write_text(content)
    status, body = request(sock_path, "POST", "api.anthropic.com", "/v1/messages")

    assert status == 403
    assert "sandbox --claude-api-key" in json.loads(body)["message"]
    assert upstream.seen == []


def test_the_key_is_read_per_request(world):
    sock_path, key_file, upstream, _ = world
    other = "sk-ant-api03-" + "o" * 40
    key_file.write_text(other + "\n")
    request(sock_path, "POST", "api.anthropic.com", "/v1/messages")
    assert upstream.seen[0]["headers"]["x-api-key"] == other


def test_event_streams_are_relayed_as_they_arrive(world):
    sock_path, _, upstream, _ = world
    sock, response = connect(
        sock_path, "POST", "api.anthropic.com", "/v1/messages?stream"
    )
    with sock:
        # The first event arrives while upstream still holds back the second.
        sock.settimeout(5)
        deadline = time.monotonic() + 5
        first = b""
        while b"event: one" not in first and time.monotonic() < deadline:
            first += response.read1(1024)
        assert first == b"event: one\n\n"
        upstream.release.set()
        assert response.read() == b"event: two\n\n"


def test_a_stale_socket_is_replaced(world):
    d = short_dir()
    (d / "api.sock").write_text("left over")
    guard = Guard("claude-api-proxy", d / "api.sock", world[1], env=base_env())
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.socket(socket.AF_UNIX) as s:
                    s.connect(str(d / "api.sock"))
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("never listened")
    finally:
        assert guard.stop()[0] == 0  # Exits cleanly on SIGTERM.
