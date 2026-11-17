"""Tests for nix/patches/forgejo-api-unix-socket.patch (applied to
forgejo-cli's vendored forgejo-api crate in nix/package.nix), and fj end to
end through src/forgejo-api-proxy.

With FJ_HTTP_UNIX_SOCKET set, the patched fj must send its API requests over
that socket as plain HTTP, with the real host in Host - that's what the
sandbox's API proxy relies on. Without it, fj must behave as unpatched. Fails
if a bump makes the patch stop applying (the build fails) or stop having an
effect (these tests fail).

FJ_BIN points the tests at another fj build than the one on PATH.
"""

import http.client
import json
import os
import shutil
import socket
import subprocess
import threading

import pytest
from conftest import FakeProxy, load_module

FJ = os.environ.get("FJ_BIN") or shutil.which("fj")
pytestmark = pytest.mark.skipif(FJ is None, reason="needs fj")

HOST = "forgejo.example"


def run_fj(home, *args, env=None):
    clean = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("FJ_")
        and k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")
    }
    return subprocess.run(
        [FJ, "--host", HOST, "--style", "minimal", *args],
        env={
            **clean,
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CACHE_HOME": str(home / "cache"),
            **(env or {}),
        },
        cwd=home,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.fixture
def short_tmp(tmp_path_factory):
    # Unix socket paths are limited to ~108 bytes; pytest's tmp_path can exceed it.
    return tmp_path_factory.mktemp("fjs", numbered=True)


def test_request_arrives_as_plain_http_with_the_real_host(short_tmp):
    proxy = FakeProxy(short_tmp / "s", {"login": "via-socket"})
    try:
        result = run_fj(short_tmp, "whoami", env={"FJ_HTTP_UNIX_SOCKET": str(short_tmp / "s")})
    finally:
        proxy.close()

    assert result.returncode == 0, result.stderr
    assert "via-socket" in result.stdout
    # fj always appends a query string, empty or not.
    [request] = proxy.requests
    assert request["line"].startswith("GET /api/v1/user")
    assert request["line"].endswith(" HTTP/1.1")
    assert request["headers"]["host"] == HOST


def test_without_the_variable_fj_connects_directly(short_tmp):
    """Unset, the patch changes nothing: fj opens a normal TLS connection,
    seen here as a CONNECT to a local HTTPS_PROXY that refuses it."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    seen = []

    def accept():
        conn, _ = listener.accept()
        with conn:
            seen.append(conn.recv(4096).split(b"\r\n", 1)[0])
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        result = run_fj(
            short_tmp, "whoami", env={"HTTPS_PROXY": f"http://127.0.0.1:{listener.getsockname()[1]}"}
        )
        thread.join(timeout=10)
    finally:
        listener.close()

    assert result.returncode != 0
    assert seen == [f"CONNECT {HOST}:443 HTTP/1.1".encode()]


# -- end to end through forgejo-api-proxy ----------------------------------------


class Confirm:
    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def __call__(self, description, cmdline):
        self.prompts.append(description)
        return self.answer


@pytest.fixture
def fj_via_proxy(short_tmp):
    """Run fj through a real forgejo-api-proxy to FakeProxy as upstream."""
    proxy_module = load_module("forgejo-api-proxy")
    upstream = FakeProxy(short_tmp / "up", {"login": "someone", "id": 1})
    servers = []

    def run(*args, answer=None):
        confirm = Confirm(answer)
        sock = str(short_tmp / f"p{len(servers)}")
        server = proxy_module.ProxyServer(
            sock,
            tokens=lambda: {HOST: "real-token"},
            upstream=lambda host: UnixHTTPConnection(str(short_tmp / "up")),
            confirm=confirm,
        )
        servers.append(server)
        threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
        return run_fj(short_tmp, *args, env={"FJ_HTTP_UNIX_SOCKET": sock}), confirm

    yield run, upstream
    for server in servers:
        server.shutdown()
        server.server_close()
    upstream.close()


class UnixHTTPConnection(http.client.HTTPConnection):
    """Upstream for the proxy: FakeProxy's socket instead of TLS to the host."""

    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def test_read_gets_the_real_token(fj_via_proxy):
    run, upstream = fj_via_proxy
    result, confirm = run("whoami")

    assert result.returncode == 0, result.stderr
    assert "someone" in result.stdout
    assert {r["headers"]["authorization"] for r in upstream.requests} == {"token real-token"}
    assert confirm.prompts == []


def test_declined_write_fails_in_fj_and_never_reaches_forgejo(fj_via_proxy):
    run, upstream = fj_via_proxy
    result, confirm = run("issue", "comment", "o/r#1", "hello", answer=None)

    assert result.returncode != 0
    assert "declined by user" in result.stderr
    assert not [r for r in upstream.requests if not r["line"].startswith(("GET ", "HEAD "))]
    assert confirm.prompts == [f"POST {HOST}/api/v1/repos/o/r/issues/1/comments?"]


def test_approved_write_goes_through_with_the_real_token(fj_via_proxy):
    run, upstream = fj_via_proxy
    result, confirm = run("issue", "comment", "o/r#1", "hello", answer="once")

    [post] = [r for r in upstream.requests if r["line"].startswith("POST ")]
    assert json.loads(post["body"])["body"] == "hello"
    assert post["headers"]["authorization"] == "token real-token"
    assert len(confirm.prompts) == 1
