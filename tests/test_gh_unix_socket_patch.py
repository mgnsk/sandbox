"""Tests for nix/patches/gh-unix-socket.patch (applied to gh in nix/package.nix).

With GH_HTTP_UNIX_SOCKET set, the patched gh must send its API requests over
that socket as plain HTTP, with the real host in Host - that's what the
sandbox's API proxy relies on. Without it, gh must behave as unpatched. Fails
if a gh bump makes the patch stop applying (the build fails) or stop having
an effect (these tests fail).

GH_BIN points the tests at another gh build than the one on PATH.
"""

import json
import os
import shutil
import socket
import subprocess
import threading

import pytest
from conftest import FakeProxy

GH = os.environ.get("GH_BIN") or shutil.which("gh")
pytestmark = pytest.mark.skipif(GH is None, reason="needs gh")


def run_gh(tmp_path, *args, env=None):
    clean = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GH_") and k not in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
    }
    return subprocess.run(
        [GH, *args],
        env={
            **clean,
            "HOME": str(tmp_path),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "XDG_STATE_HOME": str(tmp_path / "state"),
            "GH_TOKEN": "placeholder",
            "GH_NO_UPDATE_NOTIFIER": "1",
            **(env or {}),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.fixture
def short_tmp(tmp_path_factory):
    # Unix socket paths are limited to ~108 bytes; pytest's tmp_path can exceed it.
    return tmp_path_factory.mktemp("ghs", numbered=True)


def test_rest_request_arrives_as_plain_http_with_the_real_host(short_tmp):
    proxy = FakeProxy(short_tmp / "s", {"login": "via-socket"})
    try:
        result = run_gh(
            short_tmp, "api", "user", "--jq", ".login", env={"GH_HTTP_UNIX_SOCKET": str(short_tmp / "s")}
        )
    finally:
        proxy.close()

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "via-socket"
    [request] = proxy.requests
    assert request["line"] == "GET /user HTTP/1.1"
    assert request["headers"]["host"] == "api.github.com"
    assert request["headers"]["authorization"] == "token placeholder"


def test_graphql_request_arrives_with_its_body(short_tmp):
    proxy = FakeProxy(short_tmp / "s", {"data": {"viewer": {"login": "via-socket"}}})
    try:
        result = run_gh(
            short_tmp,
            "api",
            "graphql",
            "-f",
            "query={ viewer { login } }",
            "--jq",
            ".data.viewer.login",
            env={"GH_HTTP_UNIX_SOCKET": str(short_tmp / "s")},
        )
    finally:
        proxy.close()

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "via-socket"
    [request] = proxy.requests
    assert request["line"] == "POST /graphql HTTP/1.1"
    assert request["headers"]["host"] == "api.github.com"
    assert json.loads(request["body"])["query"] == "{ viewer { login } }"


def test_without_the_variable_gh_connects_directly(short_tmp):
    """Unset, the patch changes nothing: gh opens a normal TLS connection,
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
        result = run_gh(
            short_tmp,
            "api",
            "user",
            env={"HTTPS_PROXY": f"http://127.0.0.1:{listener.getsockname()[1]}"},
        )
        thread.join(timeout=10)
    finally:
        listener.close()

    assert result.returncode != 0
    assert seen == [b"CONNECT api.github.com:443 HTTP/1.1"]
