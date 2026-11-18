"""Tests for bin/forgejo-api-proxy: which hosts and tokens it takes from the
host fj's keys.json, and its server with a fake upstream on loopback standing
in for a Forgejo instance. The shared mechanics (refusals, streaming) are
covered through gh-api-proxy's tests."""

import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import connect, https_send, load_module, serve

proxy = load_module("forgejo-api-proxy")

HOST = "forgejo.example"


class FakeForgejo(BaseHTTPRequestHandler):
    """Records each request; answers every one with its path."""

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
        out = json.dumps({"login": "someone", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
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


def write_keys(path, hosts):
    path.write_text(json.dumps({"hosts": hosts, "aliases": {}, "default_ssh": []}))


# -- keys.json -----------------------------------------------------------------


def test_tokens_come_from_every_login_type(tmp_path):
    keys = tmp_path / "keys.json"
    write_keys(
        keys,
        {
            "a.example": {"type": "Application", "token": "app"},
            "b.example:3000/forgejo": {
                "type": "OAuth",
                "token": "oauth",
                "refresh_token": "r",
                "expires_at": "2030-01-01T00:00:00Z",
            },
        },
    )
    assert proxy.host_tokens(keys) == {"a.example": "app", "b.example:3000": "oauth"}


@pytest.mark.parametrize(
    "content", [None, "", "not json", "[]", '{"hosts": []}', '{"hosts": {"a": 1}}']
)
def test_missing_or_odd_keys_file_means_no_hosts(tmp_path, content):
    keys = tmp_path / "keys.json"
    if content is not None:
        keys.write_text(content)
    assert proxy.host_tokens(keys) == {}


def test_project_tokens_keep_only_well_formed_entries(tmp_path):
    tokens = tmp_path / "forgejo-tokens.json"
    assert proxy.api_proxy.read_tokens(tokens) == {}
    tokens.write_text(
        json.dumps({"A.example": "aaaaaaaa", "b.example": "bad token", "c": 1})
    )
    assert proxy.api_proxy.read_tokens(tokens) == {"a.example": "aaaaaaaa"}
    tokens.write_text("[]")
    assert proxy.api_proxy.read_tokens(tokens) == {}


def test_keys_path_follows_xdg_data_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert proxy.keys_path() == tmp_path / "forgejo-cli" / "keys.json"


# -- server --------------------------------------------------------------------


@pytest.fixture
def upstream():
    FakeForgejo.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeForgejo)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    yield server
    server.shutdown()


@pytest.fixture
def make_proxy(upstream):
    servers = []

    def make(tokens, answer=None):
        confirm = Confirm(answer)
        port = upstream.server_address[1]
        server = serve(
            proxy.ProxyServer(
                tokens=lambda: dict(tokens),
                upstream=lambda host: http.client.HTTPConnection(
                    "127.0.0.1", port, timeout=10
                ),
                confirm=confirm,
            )
        )
        servers.append(server)
        return server, confirm

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


def request(server, method, host, path, body=b"", headers=()):
    """Send a request through a tunnel to host; return (status, body)."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", *headers]
    if body or method not in ("GET", "HEAD"):
        lines.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    target = host if ":" in host else f"{host}:443"
    status, _, out = https_send(server, target, raw)
    return status, out


def test_read_gets_the_hosts_token_without_a_prompt(make_proxy):
    path, confirm = make_proxy({HOST: "real"})
    status, _ = request(
        path, "GET", HOST, "/api/v1/user", headers=["Authorization: token fake"]
    )
    assert status == 200
    [seen] = FakeForgejo.seen
    assert seen["headers"]["Authorization"] == "token real"
    assert seen["headers"]["Host"] == HOST
    assert confirm.prompts == []


def test_host_with_a_port_keeps_it(make_proxy):
    path, _ = make_proxy({f"{HOST}:3000": "real"})
    assert request(path, "GET", f"{HOST}:3000", "/api/v1/user")[0] == 200
    assert FakeForgejo.seen[0]["headers"]["Host"] == f"{HOST}:3000"


@pytest.mark.parametrize("host", ["other.example", f"{HOST}:3000"])
def test_hosts_not_logged_in_on_the_host_are_refused(make_proxy, host):
    path, _ = make_proxy({HOST: "real"})
    status, body = request(path, "GET", host, "/api/v1/user")
    assert status == 403
    assert json.loads(body)["message"].startswith("forgejo-api-proxy:")
    assert FakeForgejo.seen == []


def test_nothing_is_tunneled_unread(make_proxy):
    """Every host is intercepted, so one not logged in gets the refusal
    above rather than a tunnel to the host's own services."""
    server, _ = make_proxy({HOST: "real"})
    assert not server.tunnel_allowed("127.0.0.1:22")
    sock, head = connect(server, "127.0.0.1:22")
    sock.close()
    assert " 200 " in head.split("\r\n", 1)[0]  # Then the TLS handshake.


def test_refusal_says_how_to_log_in(make_proxy):
    path, _ = make_proxy({})
    _, body = request(path, "GET", HOST, "/api/v1/user")
    assert f"fj --host {HOST} auth add-token" in json.loads(body)["message"]


def test_a_login_on_the_host_applies_without_a_restart(make_proxy):
    tokens = {}
    path, _ = make_proxy(tokens)  # Read again on every request.
    assert request(path, "GET", HOST, "/api/v1/user")[0] == 403
    tokens[HOST] = "real"
    assert request(path, "GET", HOST, "/api/v1/user")[0] == 200


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_declined_write_never_reaches_upstream(make_proxy, method):
    path, confirm = make_proxy({HOST: "real"})
    status, body = request(
        path, method, HOST, "/api/v1/repos/o/r/issues", b'{"title":"x"}'
    )
    assert status == 403
    assert "declined by user" in json.loads(body)["message"]
    assert FakeForgejo.seen == []
    assert confirm.prompts == [f"{method} {HOST}/api/v1/repos/o/r/issues"]


def test_approved_write_goes_through_with_its_body(make_proxy):
    path, _ = make_proxy({HOST: "real"}, answer="once")
    status, _ = request(
        path, "POST", HOST, "/api/v1/repos/o/r/issues", b'{"title":"x"}'
    )
    assert status == 200
    [seen] = FakeForgejo.seen
    assert (seen["body"], seen["headers"]["Authorization"]) == (
        b'{"title":"x"}',
        "token real",
    )
