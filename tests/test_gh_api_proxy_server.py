"""Tests for src/gh-api-proxy's server (and api_proxy's HTTPS proxy under
it): CONNECT and interception, forwarding, token handling, refusals,
approvals and streaming, with an in-process proxy and a fake upstream on
loopback standing in for GitHub."""

import http.client
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import connect, https_send, load_module, serve, tls_wrap

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


def to(server):
    """upstream/tunnel openers for the proxy, all going to server."""
    port = server.server_address[1]
    return {
        "upstream": lambda host: http.client.HTTPConnection(
            "127.0.0.1", port, timeout=10
        ),
        "tunnel": lambda name, _port: socket.create_connection(
            ("127.0.0.1", port), timeout=10
        ),
    }


@pytest.fixture
def make_proxy(upstream):
    servers = []

    def make(answer=None):
        confirm = Confirm(answer)
        server = serve(proxy.ProxyServer(REAL_TOKEN, confirm=confirm, **to(upstream)))
        servers.append(server)
        return server, confirm

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


def send(server, raw, target="api.github.com:443"):
    """Send a raw request through a tunnel to target; (status, headers, body)."""
    return https_send(server, target, raw)


def request(server, method, host, path, body=b"", headers=()):
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "Authorization: token placeholder",
    ]
    lines += list(headers)
    if body or method not in ("GET", "HEAD"):
        lines.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    return send(server, raw, f"{host}:443")


# -- forwarding and the token --------------------------------------------------


def test_read_is_forwarded_with_the_real_token(make_proxy):
    server, confirm = make_proxy()
    status, _, body = request(server, "GET", "api.github.com", "/user")

    assert status == 200
    assert json.loads(body) == {"path": "/user"}
    [seen] = FakeUpstream.seen
    assert seen["headers"]["Host"] == "api.github.com"
    assert seen["headers"]["Authorization"] == f"token {REAL_TOKEN}"
    assert confirm.prompts == []


def test_download_host_is_tunneled_unread(make_proxy):
    """Plain HTTP here, as the tunnel never looks: the client's own
    Authorization arrives, and no token is added."""
    server, _ = make_proxy()
    sock, head = connect(server, "objects.githubusercontent.com:443")
    assert " 200 " in head.split("\r\n", 1)[0]
    with sock:
        sock.sendall(
            b"GET /asset HTTP/1.1\r\nHost: objects.githubusercontent.com\r\n"
            b"Authorization: token placeholder\r\n\r\n"
        )
        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        assert response.status == 200
        assert json.loads(response.read()) == {"path": "/asset"}
    [seen] = FakeUpstream.seen
    assert seen["headers"]["Authorization"] == "token placeholder"


def test_hop_by_hop_and_expect_headers_are_not_forwarded(make_proxy):
    server, _ = make_proxy()
    request(
        server,
        "GET",
        "api.github.com",
        "/user",
        headers=["Connection: keep-alive", "X-Custom: kept"],
    )

    [seen] = FakeUpstream.seen
    assert seen["headers"]["X-Custom"] == "kept"
    assert seen["headers"].get("Connection") != "keep-alive"


# -- the proxy itself ----------------------------------------------------------


@pytest.mark.parametrize("auth", [False, "Basic c2FuZGJveDp3cm9uZw=="])
def test_connect_needs_the_secret(make_proxy, auth):
    server, _ = make_proxy()
    sock, head = connect(server, "api.github.com:443", auth=auth)
    sock.close()
    assert head.startswith("HTTP/1.1 407 ")
    assert FakeUpstream.seen == []


@pytest.mark.parametrize("target", ["api.github.com", "a b:443", "[::1]:443"])
def test_bad_connect_target_is_refused(make_proxy, target):
    server, _ = make_proxy()
    sock, head = connect(server, target)
    sock.close()
    assert head.startswith("HTTP/1.1 400 ")


def test_plain_http_proxying_is_refused(make_proxy):
    server, _ = make_proxy()
    with socket.create_connection(server.server_address[:2], timeout=10) as sock:
        sock.sendall(
            b"GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        )
        assert sock.recv(64).startswith(b"HTTP/1.1 405 ")


def test_the_proxy_url_carries_the_secret(make_proxy):
    server, _ = make_proxy()
    port = server.server_address[1]
    assert server.proxy_url == f"http://sandbox:{server.secret}@127.0.0.1:{port}"


def test_announce_writes_the_ca_and_then_the_port_and_secret(make_proxy, tmp_path):
    server, _ = make_proxy()
    server.announce(tmp_path)

    assert (tmp_path / "ca.pem").read_bytes() == server.ca.pem()
    info = json.loads((tmp_path / "proxy.json").read_text())
    assert info == {"port": server.server_address[1], "secret": server.secret}
    assert (tmp_path / "proxy.json").stat().st_mode & 0o077 == 0


def test_each_proxy_has_its_own_ca_and_secret(make_proxy):
    (a, _), (b, _) = make_proxy(), make_proxy()
    assert a.ca.pem() != b.ca.pem()
    assert a.secret != b.secret


def test_another_ca_isnt_trusted_by_the_client(make_proxy):
    a, _ = make_proxy()
    b, _ = make_proxy()
    sock, _ = connect(a, "api.github.com:443")
    with pytest.raises(ssl.SSLCertVerificationError):
        tls_wrap(sock, b, "api.github.com")
    sock.close()


# -- refusals ------------------------------------------------------------------


def assert_refused(result, status):
    got, _, body = result
    assert got == status
    assert json.loads(body)["message"].startswith("gh-api-proxy:")
    assert FakeUpstream.seen == []


def test_unknown_host_is_refused(make_proxy):
    server, _ = make_proxy()
    assert_refused(request(server, "GET", "example.com", "/"), 403)


def test_host_other_than_the_connect_target_is_refused(make_proxy):
    server, _ = make_proxy()
    assert_refused(
        send(
            server,
            b"GET /asset HTTP/1.1\r\nHost: objects.githubusercontent.com\r\n\r\n",
        ),
        421,
    )


def test_two_host_headers_are_refused(make_proxy):
    server, _ = make_proxy()
    assert_refused(
        send(
            server,
            b"GET /user HTTP/1.1\r\nHost: api.github.com\r\nHost: example.com\r\n\r\n",
        ),
        421,
    )


def test_two_content_lengths_are_refused(make_proxy):
    server, _ = make_proxy()
    assert_refused(
        send(
            server,
            b"GET /user HTTP/1.1\r\nHost: api.github.com\r\n"
            b"Content-Length: 0\r\nContent-Length: 5\r\n\r\n",
        ),
        400,
    )


def test_chunked_request_body_is_refused(make_proxy):
    server, _ = make_proxy()
    assert_refused(
        send(
            server,
            b"POST /repos/o/r/labels HTTP/1.1\r\nHost: api.github.com\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ),
        411,
    )


def test_absolute_form_target_is_refused(make_proxy):
    server, _ = make_proxy()
    assert_refused(
        send(
            server,
            b"GET https://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        ),
        400,
    )


def test_oversized_graphql_body_is_refused(make_proxy, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_GRAPHQL_BODY", 10)
    server, _ = make_proxy()
    assert_refused(
        request(server, "POST", "api.github.com", "/graphql", b"x" * 11), 413
    )


def test_unreachable_upstream_is_a_502():
    server = serve(
        proxy.ProxyServer(
            REAL_TOKEN,
            upstream=lambda host: http.client.HTTPConnection("127.0.0.1", 1, timeout=2),
            confirm=Confirm(None),
        )
    )
    try:
        status, _, _ = request(server, "GET", "api.github.com", "/user")
    finally:
        server.shutdown()
        server.server_close()
    assert status == 502


# -- approvals -----------------------------------------------------------------


def test_declined_write_never_reaches_upstream(make_proxy):
    server, confirm = make_proxy(answer=None)
    assert_refused(
        request(server, "POST", "api.github.com", "/repos/o/r/labels", b'{"name":"x"}'),
        403,
    )
    assert confirm.prompts == ["POST api.github.com/repos/o/r/labels"]


def test_the_popup_names_no_process(make_proxy):
    """The peer is pasta, not the requesting process."""
    seen = []
    server, _ = make_proxy()
    server.confirm = lambda description, cmdline: seen.append(cmdline)
    request(server, "DELETE", "api.github.com", "/repos/o/r/labels/x")
    assert seen == [None]


def test_write_approved_once_is_forwarded_and_the_next_one_asks_again(make_proxy):
    server, confirm = make_proxy(answer="once")
    for _ in range(2):
        status, _, _ = request(
            server, "POST", "api.github.com", "/repos/o/r/labels", b'{"name":"x"}'
        )
        assert status == 200

    assert [s["body"] for s in FakeUpstream.seen] == [b'{"name":"x"}'] * 2
    assert len(confirm.prompts) == 2


def test_approve_always_covers_later_writes(make_proxy):
    server, confirm = make_proxy(answer="always")
    for label in ("x", "y"):
        status, _, _ = request(
            server, "DELETE", "api.github.com", f"/repos/o/r/labels/{label}"
        )
        assert status == 200

    assert len(confirm.prompts) == 1
    assert len(FakeUpstream.seen) == 2


def test_a_new_proxy_asks_again(make_proxy):
    """A new sandbox starts a new proxy, and "always" dies with the old one."""
    for _ in range(2):
        server, confirm = make_proxy(answer="always")
        status, _, _ = request(
            server, "DELETE", "api.github.com", "/repos/o/r/labels/x"
        )
        assert status == 200
        assert len(confirm.prompts) == 1


def test_graphql_query_is_forwarded_without_a_prompt(make_proxy):
    server, confirm = make_proxy()
    body = json.dumps({"query": "{ viewer { login } }"}).encode()
    status, _, _ = request(server, "POST", "api.github.com", "/graphql", body)

    assert status == 200
    assert confirm.prompts == []
    assert FakeUpstream.seen[0]["body"] == body


def test_graphql_mutation_prompts(make_proxy):
    server, confirm = make_proxy(answer=None)
    body = json.dumps(
        {"query": "mutation { addStar(input: {}) { clientMutationId } }"}
    ).encode()
    assert_refused(request(server, "POST", "api.github.com", "/graphql", body), 403)
    assert "mutation (anonymous): addStar" in confirm.prompts[0]


# -- responses -----------------------------------------------------------------


def test_large_chunked_response_is_relayed_in_full(make_proxy):
    server, _ = make_proxy()
    status, _, body = request(server, "GET", "api.github.com", "/big")
    assert status == 200
    assert body == BIG


def test_redirect_is_passed_back_to_the_client(make_proxy):
    server, _ = make_proxy()
    status, headers, _ = request(server, "GET", "api.github.com", "/redirect")
    assert status == 302
    assert headers["Location"] == "https://objects.githubusercontent.com/asset"


def test_head_has_headers_but_no_body(make_proxy):
    server, _ = make_proxy()
    status, headers, body = request(server, "HEAD", "api.github.com", "/user")
    assert status == 200
    assert int(headers["Content-Length"]) > 0
    assert body == b""


def test_request_body_is_streamed_upstream(make_proxy):
    server, _ = make_proxy(answer="once")
    payload = bytes(range(256)) * 4096
    status, _, _ = request(
        server, "POST", "uploads.github.com", "/repos/o/r/releases/1/assets", payload
    )
    assert status == 200
    [seen] = FakeUpstream.seen
    assert seen["body"] == payload
    assert seen["headers"]["Authorization"] == f"token {REAL_TOKEN}"
