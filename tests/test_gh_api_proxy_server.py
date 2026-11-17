"""Tests for bin/gh-api-proxy's server: forwarding, token handling, refusals,
approvals and streaming, with an in-process proxy and a fake upstream on
loopback standing in for GitHub."""

import http.client
import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import load_module

proxy = load_module("gh-api-proxy")

REAL_TOKEN = "real-token"
BIG = b"x" * (1024 * 1024 + 7)


class FakeUpstream(BaseHTTPRequestHandler):
    """Records each request; answers by path."""

    protocol_version = "HTTP/1.1"
    seen = []

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
        if self.path == "/big":
            # Chunked, so the proxy has to relay it close-delimited.
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(BIG), 100_000):
                chunk = BIG[i : i + 100_000]
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://objects.githubusercontent.com/asset")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        out = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = answer


class Confirm:
    """Stands in for the popup: records each prompt, gives a fixed answer."""

    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def __call__(self, description, cmdline):
        self.prompts.append(description)
        return self.answer


@pytest.fixture
def upstream():
    FakeUpstream.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    yield server
    server.shutdown()


def start_proxy(tmp_path_factory, upstream, confirm):
    path = str(tmp_path_factory.mktemp("p") / "s")
    port = upstream.server_address[1]
    server = proxy.ProxyServer(
        path,
        REAL_TOKEN,
        upstream=lambda host: http.client.HTTPConnection("127.0.0.1", port, timeout=10),
        confirm=confirm,
    )
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    return server, path


@pytest.fixture
def make_proxy(tmp_path_factory, upstream):
    servers = []

    def make(answer=None):
        confirm = Confirm(answer)
        server, path = start_proxy(tmp_path_factory, upstream, confirm)
        servers.append(server)
        return path, confirm

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


def send(sock_path, raw):
    """Send a raw request; return (status, headers, body)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    try:
        sock.sendall(raw)
        response = http.client.HTTPResponse(sock, method=raw.split(b" ", 1)[0].decode())
        response.begin()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        sock.close()


def request(sock_path, method, host, path, body=b"", headers=()):
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "Authorization: token placeholder",
    ]
    lines += list(headers)
    if body or method not in ("GET", "HEAD"):
        lines.append(f"Content-Length: {len(body)}")
    return send(sock_path, ("\r\n".join(lines) + "\r\n\r\n").encode() + body)


# -- forwarding and the token --------------------------------------------------


def test_read_is_forwarded_with_the_real_token(make_proxy):
    path, confirm = make_proxy()
    status, _, body = request(path, "GET", "api.github.com", "/user")

    assert status == 200
    assert json.loads(body) == {"path": "/user"}
    [seen] = FakeUpstream.seen
    assert seen["headers"]["Host"] == "api.github.com"
    assert seen["headers"]["Authorization"] == f"token {REAL_TOKEN}"
    assert confirm.prompts == []


def test_non_api_host_gets_no_token(make_proxy):
    path, _ = make_proxy()
    status, _, _ = request(path, "GET", "objects.githubusercontent.com", "/asset")

    assert status == 200
    [seen] = FakeUpstream.seen
    assert "Authorization" not in seen["headers"]


def test_hop_by_hop_and_expect_headers_are_not_forwarded(make_proxy):
    path, _ = make_proxy()
    request(
        path,
        "GET",
        "api.github.com",
        "/user",
        headers=["Connection: keep-alive", "X-Custom: kept"],
    )

    [seen] = FakeUpstream.seen
    assert seen["headers"]["X-Custom"] == "kept"
    assert seen["headers"].get("Connection") != "keep-alive"


# -- refusals ------------------------------------------------------------------


def assert_refused(result, status):
    got, _, body = result
    assert got == status
    assert json.loads(body)["message"].startswith("gh-api-proxy:")
    assert FakeUpstream.seen == []


def test_unknown_host_is_refused(make_proxy):
    path, _ = make_proxy()
    assert_refused(request(path, "GET", "example.com", "/"), 403)


def test_two_host_headers_are_refused(make_proxy):
    path, _ = make_proxy()
    assert_refused(
        send(
            path,
            b"GET /user HTTP/1.1\r\nHost: api.github.com\r\nHost: example.com\r\n\r\n",
        ),
        403,
    )


def test_two_content_lengths_are_refused(make_proxy):
    path, _ = make_proxy()
    assert_refused(
        send(
            path,
            b"GET /user HTTP/1.1\r\nHost: api.github.com\r\n"
            b"Content-Length: 0\r\nContent-Length: 5\r\n\r\n",
        ),
        400,
    )


def test_chunked_request_body_is_refused(make_proxy):
    path, _ = make_proxy()
    assert_refused(
        send(
            path,
            b"POST /repos/o/r/labels HTTP/1.1\r\nHost: api.github.com\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ),
        411,
    )


def test_absolute_form_target_is_refused(make_proxy):
    path, _ = make_proxy()
    assert_refused(
        send(
            path,
            b"GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        ),
        400,
    )


def test_oversized_graphql_body_is_refused(make_proxy, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_GRAPHQL_BODY", 10)
    path, _ = make_proxy()
    assert_refused(request(path, "POST", "api.github.com", "/graphql", b"x" * 11), 413)


def test_unreachable_upstream_is_a_502(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("p") / "s")
    server = proxy.ProxyServer(
        path,
        REAL_TOKEN,
        upstream=lambda host: http.client.HTTPConnection("127.0.0.1", 1, timeout=2),
        confirm=Confirm(None),
    )
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    try:
        status, _, _ = request(path, "GET", "api.github.com", "/user")
    finally:
        server.shutdown()
        server.server_close()
    assert status == 502


# -- approvals -----------------------------------------------------------------


def test_declined_write_never_reaches_upstream(make_proxy):
    path, confirm = make_proxy(answer=None)
    assert_refused(
        request(path, "POST", "api.github.com", "/repos/o/r/labels", b'{"name":"x"}'),
        403,
    )
    assert confirm.prompts == ["POST api.github.com/repos/o/r/labels"]


def test_write_approved_once_is_forwarded_and_the_next_one_asks_again(make_proxy):
    path, confirm = make_proxy(answer="once")
    for _ in range(2):
        status, _, _ = request(
            path, "POST", "api.github.com", "/repos/o/r/labels", b'{"name":"x"}'
        )
        assert status == 200

    assert [s["body"] for s in FakeUpstream.seen] == [b'{"name":"x"}'] * 2
    assert len(confirm.prompts) == 2


def test_approve_always_covers_later_writes_from_other_processes(make_proxy):
    path, confirm = make_proxy(answer="always")
    status, _, _ = request(path, "DELETE", "api.github.com", "/repos/o/r/labels/x")
    assert status == 200

    # A separate process, as every gh invocation in a sandbox is.
    script = (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "s.connect(sys.argv[1])\n"
        "s.sendall(b'DELETE /repos/o/r/labels/y HTTP/1.1\\r\\nHost: api.github.com\\r\\n\\r\\n')\n"
        "print(s.recv(64).decode())\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert " 200 " in result.stdout

    assert len(confirm.prompts) == 1
    assert len(FakeUpstream.seen) == 2


def test_a_new_proxy_asks_again(make_proxy):
    """A new sandbox starts a new proxy, and "always" dies with the old one."""
    for _ in range(2):
        path, confirm = make_proxy(answer="always")
        status, _, _ = request(path, "DELETE", "api.github.com", "/repos/o/r/labels/x")
        assert status == 200
        assert len(confirm.prompts) == 1


def test_graphql_query_is_forwarded_without_a_prompt(make_proxy):
    path, confirm = make_proxy()
    body = json.dumps({"query": "{ viewer { login } }"}).encode()
    status, _, _ = request(path, "POST", "api.github.com", "/graphql", body)

    assert status == 200
    assert confirm.prompts == []
    assert FakeUpstream.seen[0]["body"] == body


def test_graphql_mutation_prompts(make_proxy):
    path, confirm = make_proxy(answer=None)
    body = json.dumps(
        {"query": "mutation { addStar(input: {}) { clientMutationId } }"}
    ).encode()
    assert_refused(request(path, "POST", "api.github.com", "/graphql", body), 403)
    assert "mutation (anonymous): addStar" in confirm.prompts[0]


# -- responses -----------------------------------------------------------------


def test_large_chunked_response_is_relayed_in_full(make_proxy):
    path, _ = make_proxy()
    status, _, body = request(path, "GET", "api.github.com", "/big")
    assert status == 200
    assert body == BIG


def test_redirect_is_passed_back_to_the_client(make_proxy):
    path, _ = make_proxy()
    status, headers, _ = request(path, "GET", "api.github.com", "/redirect")
    assert status == 302
    assert headers["Location"] == "https://objects.githubusercontent.com/asset"


def test_head_has_headers_but_no_body(make_proxy):
    path, _ = make_proxy()
    status, headers, body = request(path, "HEAD", "api.github.com", "/user")
    assert status == 200
    assert int(headers["Content-Length"]) > 0
    assert body == b""


def test_request_body_is_streamed_upstream(make_proxy):
    path, _ = make_proxy(answer="once")
    payload = bytes(range(256)) * 4096
    status, _, _ = request(
        path, "POST", "uploads.github.com", "/repos/o/r/releases/1/assets", payload
    )
    assert status == 200
    [seen] = FakeUpstream.seen
    assert seen["body"] == payload
    assert seen["headers"]["Authorization"] == f"token {REAL_TOKEN}"
