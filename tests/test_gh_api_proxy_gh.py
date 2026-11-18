"""End-to-end: the sandbox's gh (upstream gh in nix/packages.nix's wrapper),
through src/gh-api-proxy, to a fake upstream.

The wrapper has to win over a proxy and CA bundle already in the
environment, so the tests set decoys for both. GH_BIN points the tests at
another gh than the one on PATH - it has to be the wrapper.
"""

import http.client
import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import load_module, serve

proxy = load_module("gh-api-proxy")

REAL_TOKEN = "real-token"
RELEASE = {
    "id": 1,
    "tag_name": "v1",
    "upload_url": "https://uploads.github.com/repos/o/r/releases/1/assets{?name,label}",
    "assets": [],
}


GH = os.environ.get("GH_BIN") or shutil.which("gh")
pytestmark = pytest.mark.skipif(GH is None, reason="needs gh")


class FakeGitHub(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        pass

    def reply(self, status, payload):
        out = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def answer(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        self.seen.append(
            {
                "method": self.command,
                "host": self.headers["Host"],
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            }
        )
        if self.path == "/user":
            return self.reply(200, {"login": "someone"})
        if self.path == "/graphql":
            return self.reply(200, {"data": {"viewer": {"login": "someone"}}})
        if self.path.startswith("/repos/o/r/releases/tags/v1"):
            return self.reply(200, RELEASE)
        if self.path.startswith("/repos/o/r/releases/1/assets"):
            if self.command == "GET":
                return self.reply(200, [])
            return self.reply(201, {"id": 5, "name": "asset.txt", "state": "uploaded"})
        if self.path == "/repos/o/r/labels" and self.command == "POST":
            return self.reply(201, {"name": "x"})
        return self.reply(404, {"message": "Not Found"})

    do_GET = do_POST = do_PATCH = do_DELETE = answer


class Confirm:
    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def __call__(self, description, cmdline):
        self.prompts.append(description)
        return self.answer


@pytest.fixture
def github():
    FakeGitHub.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    yield server
    server.shutdown()


@pytest.fixture
def gh(tmp_path_factory, github):
    """Run the patched gh through a fresh proxy, whose popup gives `answer`."""
    servers = []
    home = tmp_path_factory.mktemp("home")
    port = github.server_address[1]

    def run(*args, answer=None):
        confirm = Confirm(answer)
        server = serve(
            proxy.ProxyServer(
                REAL_TOKEN,
                upstream=lambda host: http.client.HTTPConnection(
                    "127.0.0.1", port, timeout=10
                ),
                confirm=confirm,
            )
        )
        servers.append(server)
        ca_file = tmp_path_factory.mktemp("ca") / "bundle.pem"
        ca_file.write_bytes(server.ca.pem())
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("GH_", "SANDBOX_"))
            and not k.lower().endswith("_proxy")
        }
        result = subprocess.run(
            [GH, *args],
            cwd=home,
            env={
                **env,
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / "config"),
                "XDG_CACHE_HOME": str(home / "cache"),
                "XDG_STATE_HOME": str(home / "state"),
                "GH_TOKEN": "placeholder",
                "SANDBOX_GH_PROXY": server.proxy_url,
                "SANDBOX_CA_FILE": str(ca_file),
                # Decoys the wrapper has to override.
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "NO_PROXY": "*",
                "GH_NO_UPDATE_NOTIFIER": "1",
                "GH_TELEMETRY": "false",
            },
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return result, confirm

    yield run
    for server in servers:
        server.shutdown()
        server.server_close()


def test_rest_read_uses_the_real_token(gh):
    result, confirm = gh("api", "user", "--jq", ".login")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "someone"
    [seen] = FakeGitHub.seen
    assert (seen["host"], seen["headers"]["Authorization"]) == (
        "api.github.com",
        f"token {REAL_TOKEN}",
    )
    assert confirm.prompts == []


def test_graphql_query_needs_no_prompt(gh):
    result, confirm = gh(
        "api",
        "graphql",
        "-f",
        "query={ viewer { login } }",
        "--jq",
        ".data.viewer.login",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "someone"
    assert confirm.prompts == []


def test_declined_write_fails_in_gh_and_never_reaches_github(gh):
    result, confirm = gh(
        "api", "-X", "POST", "repos/o/r/labels", "-f", "name=x", answer=None
    )

    assert result.returncode != 0
    assert "declined by user" in result.stderr
    assert FakeGitHub.seen == []
    assert confirm.prompts == ["POST api.github.com/repos/o/r/labels"]


def test_approved_write_goes_through(gh):
    result, _ = gh(
        "api", "-X", "POST", "repos/o/r/labels", "-f", "name=x", answer="once"
    )

    assert result.returncode == 0, result.stderr
    [seen] = FakeGitHub.seen
    assert json.loads(seen["body"]) == {"name": "x"}


def test_release_upload_sends_a_content_length(gh, tmp_path):
    """The proxy refuses chunked request bodies, so uploads must have one."""
    asset = tmp_path / "asset.txt"
    asset.write_bytes(b"payload" * 1000)

    result, confirm = gh(
        "release", "upload", "v1", str(asset), "-R", "o/r", answer="always"
    )

    assert result.returncode == 0, result.stderr
    # gh looks the repo up with a GraphQL query (a read) first.
    [upload] = [s for s in FakeGitHub.seen if s["host"] == "uploads.github.com"]
    assert upload["method"] == "POST"
    assert upload["body"] == asset.read_bytes()
    assert upload["headers"]["Authorization"] == f"token {REAL_TOKEN}"
    assert len(confirm.prompts) == 1
