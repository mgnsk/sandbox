"""Tests for src/claude-api-proxy: which paths it forwards, the key swap, and
its server with a fake upstream on loopback standing in for the Claude API.
The shared mechanics (refusals, hop-by-hop headers) are covered through
gh-api-proxy's tests."""

import http.client
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import load_module

proxy = load_module("claude-api-proxy")

KEY = "sk-ant-api03-" + "k" * 40


class FakeApi(BaseHTTPRequestHandler):
    """Records each request; /v1/messages?stream answers as an event stream
    that waits for the test between its two events."""

    protocol_version = "HTTP/1.1"
    seen = []
    release = threading.Event()

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        pass

    def answer(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        self.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            }
        )
        if self.path == "/v1/messages?stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for event in (b"event: one\n\n", None, b"event: two\n\n"):
                if event is None:
                    self.release.wait(10)
                    continue
                self.wfile.write(f"{len(event):x}\r\n".encode() + event + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            return
        out = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = answer


@pytest.fixture
def upstream():
    FakeApi.seen = []
    FakeApi.release = threading.Event()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    yield server
    FakeApi.release.set()
    server.shutdown()


@pytest.fixture
def make_proxy(tmp_path_factory, upstream):
    servers = []

    def make(key=KEY):
        path = str(tmp_path_factory.mktemp("p") / "s")
        port = upstream.server_address[1]
        hosts = []

        def open_upstream(host):
            hosts.append(host)
            return http.client.HTTPConnection("127.0.0.1", port, timeout=10)

        server = proxy.ProxyServer(path, lambda: key, upstream=open_upstream)
        threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
        servers.append(server)
        return path, hosts

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


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
    "path, allowed",
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
def test_paths(path, allowed):
    assert proxy.path_allowed(path) is allowed


def test_read_key(tmp_path):
    key_file = tmp_path / "k"
    assert proxy.read_key(key_file) is None
    key_file.write_text(KEY + "\n")
    assert proxy.read_key(key_file) == KEY
    key_file.write_text("not a key\n")
    assert proxy.read_key(key_file) is None


def test_messages_go_upstream_with_the_real_key_only(make_proxy):
    path, hosts = make_proxy()
    status, body = request(
        path, "POST", "api.anthropic.com", "/v1/messages?beta=true", b"{}"
    )

    assert status == 200 and json.loads(body) == {"path": "/v1/messages?beta=true"}
    [seen] = FakeApi.seen
    assert hosts == ["api.anthropic.com"]
    assert seen["headers"]["Host"] == "api.anthropic.com"
    assert seen["headers"]["x-api-key"] == KEY
    assert "Authorization" not in seen["headers"]
    assert seen["headers"]["anthropic-version"] == "2023-06-01"
    assert seen["body"] == b"{}"


def test_localhost_requests_go_to_the_api(make_proxy):
    path, hosts = make_proxy()
    status, _ = request(path, "GET", "localhost", "/api/claude_code/policy_limits")

    assert status == 200
    assert hosts == ["api.anthropic.com"]
    assert FakeApi.seen[0]["headers"]["Host"] == "api.anthropic.com"


@pytest.mark.parametrize(
    "host, path, message",
    [
        ("api.anthropic.com", "/v1/files", "path not allowed"),
        ("example.com", "/v1/messages", "host not allowed"),
    ],
)
def test_refusals(make_proxy, host, path, message):
    sock_path, _ = make_proxy()
    status, body = request(sock_path, "POST", host, path)

    assert status == 403 and message in json.loads(body)["message"]
    assert FakeApi.seen == []


def test_without_a_key_it_says_how_to_set_one(make_proxy):
    path, _ = make_proxy(key=None)
    status, body = request(path, "POST", "api.anthropic.com", "/v1/messages")

    assert status == 403
    assert "sandbox --claude-api-key" in json.loads(body)["message"]
    assert FakeApi.seen == []


def test_event_streams_are_relayed_as_they_arrive(make_proxy):
    path, _ = make_proxy()
    sock, response = connect(path, "POST", "api.anthropic.com", "/v1/messages?stream")
    with sock:
        # The first event arrives while upstream still holds back the second.
        sock.settimeout(5)
        deadline = time.monotonic() + 5
        first = b""
        while b"event: one" not in first and time.monotonic() < deadline:
            first += response.read1(1024)
        assert first == b"event: one\n\n"
        FakeApi.release.set()
        assert response.read() == b"event: two\n\n"
