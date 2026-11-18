"""End-to-end: the sandbox's fj (upstream forgejo-cli in nix/packages.nix's
wrapper), through src/forgejo-api-proxy, to a fake upstream. Fails if fj
stops honouring HTTPS_PROXY or SSL_CERT_FILE.

The wrapper has to win over a proxy already in the environment, so the tests
set decoys. FJ_BIN points the tests at another fj than the one on PATH - it
has to be the wrapper.
"""

import http.client
import json
import os
import shutil
import socket
import subprocess

import pytest
from conftest import FakeProxy, load_module, serve

FJ = os.environ.get("FJ_BIN") or shutil.which("fj")
pytestmark = pytest.mark.skipif(FJ is None, reason="needs fj")

HOST = "forgejo.example"


def run_fj(home, *args, env=None):
    clean = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FJ_", "SANDBOX_")) and not k.lower().endswith("_proxy")
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
        server = serve(
            proxy_module.ProxyServer(
                tokens=lambda: {HOST: "real-token"},
                upstream=lambda host: UnixHTTPConnection(str(short_tmp / "up")),
                confirm=confirm,
            )
        )
        servers.append(server)
        ca_file = short_tmp / f"ca{len(servers)}.pem"
        ca_file.write_bytes(server.ca.pem())
        env = {
            "SANDBOX_FJ_PROXY": server.proxy_url,
            "SANDBOX_CA_FILE": str(ca_file),
            # Decoys the wrapper has to override.
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
            "NO_PROXY": "*",
        }
        return run_fj(short_tmp, *args, env=env), confirm

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
    assert {r["headers"]["authorization"] for r in upstream.requests} == {
        "token real-token"
    }
    assert confirm.prompts == []


def test_declined_write_fails_in_fj_and_never_reaches_forgejo(fj_via_proxy):
    run, upstream = fj_via_proxy
    result, confirm = run("issue", "comment", "o/r#1", "hello", answer=None)

    assert result.returncode != 0
    assert "declined by user" in result.stderr
    assert not [
        r for r in upstream.requests if not r["line"].startswith(("GET ", "HEAD "))
    ]
    assert confirm.prompts == [f"POST {HOST}/api/v1/repos/o/r/issues/1/comments?"]


def test_approved_write_goes_through_with_the_real_token(fj_via_proxy):
    run, upstream = fj_via_proxy
    result, confirm = run("issue", "comment", "o/r#1", "hello", answer="once")

    [post] = [r for r in upstream.requests if r["line"].startswith("POST ")]
    assert json.loads(post["body"])["body"] == "hello"
    assert post["headers"]["authorization"] == "token real-token"
    assert len(confirm.prompts) == 1
