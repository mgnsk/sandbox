"""End-to-end: the sandbox's gh (upstream gh in nix/packages.nix's wrapper),
through gh-api-proxy run as a program, to a stand-in for GitHub.

The wrapper has to win over a proxy and CA bundle already in the
environment, so the tests set decoys for both. GH_BIN points the tests at
another gh than the one on PATH - it has to be the wrapper.
"""

import json
import os
import shutil
import subprocess

import pytest
from guards import FakeCA, FakePopups, Guard, ProxyInfo, Upstream, base_env, short_dir

TOKEN = "github_pat_project0123"
RELEASE = {
    "id": 1,
    "tag_name": "v1",
    "upload_url": "https://uploads.github.com/repos/o/r/releases/1/assets{?name,label}",
    "assets": [],
}

GH = os.environ.get("GH_BIN") or shutil.which("gh")
pytestmark = pytest.mark.skipif(GH is None, reason="needs gh")


def github(h, _body):
    """GitHub's answers to what the tests' gh commands ask."""

    def reply(status, payload):
        out = json.dumps(payload).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json; charset=utf-8")
        h.send_header("Content-Length", str(len(out)))
        h.end_headers()
        h.wfile.write(out)
        return True

    if h.path == "/user":
        return reply(200, {"login": "someone"})
    if h.path == "/graphql":
        return reply(200, {"data": {"viewer": {"login": "someone"}}})
    if h.path.startswith("/repos/o/r/releases/tags/v1"):
        return reply(200, RELEASE)
    if h.path.startswith("/repos/o/r/releases/1/assets"):
        if h.command == "GET":
            return reply(200, [])
        return reply(201, {"id": 5, "name": "asset.txt", "state": "uploaded"})
    if h.path == "/repos/o/r/labels" and h.command == "POST":
        return reply(201, {"name": "x"})
    return reply(404, {"message": "Not Found"})


@pytest.fixture
def gh():
    """Run the wrapped gh through a fresh proxy, whose popups get `answer`."""
    d = short_dir()
    ca = FakeCA(d)
    upstream = Upstream(ca)
    upstream.route = github
    popups = FakePopups(d / "popup.sock")
    (d / "github-token").write_text(TOKEN + "\n")
    guards = []
    home = d / "home"
    home.mkdir()

    def run(*args, answer=b"no"):
        popups.answer = answer
        popups.requests.clear()
        state = d / f"proxy{len(guards)}"
        state.mkdir()
        env = base_env(
            SSL_CERT_FILE=ca.file,
            SANDBOX_TEST_UPSTREAM=upstream.address,
            SANDBOX_POPUP_SOCKET=popups.path,
        )
        guards.append(
            Guard(
                "gh-api-proxy",
                state,
                d / "github-token",
                env=env,
                ready=state / "proxy.json",
            )
        )
        info = ProxyInfo(state)
        (state / "bundle.pem").write_text(info.ca_pem)
        clean = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("GH_", "SANDBOX_"))
            and not k.lower().endswith("_proxy")
        }
        result = subprocess.run(
            [GH, *args],
            cwd=home,
            env={
                **clean,
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / "config"),
                "XDG_CACHE_HOME": str(home / "cache"),
                "XDG_STATE_HOME": str(home / "state"),
                "GH_TOKEN": "placeholder",
                "SANDBOX_GH_PROXY": info.url,
                "SANDBOX_CA_FILE": str(state / "bundle.pem"),
                # Decoys the wrapper has to override.
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "NO_PROXY": "*",
                "SSL_CERT_FILE": str(ca.file),
                "GH_NO_UPDATE_NOTIFIER": "1",
                "GH_TELEMETRY": "false",
            },
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return result, popups.texts

    yield run, upstream
    for guard in guards:
        guard.stop()
    popups.close()
    upstream.close()


def test_rest_read_uses_the_real_token(gh):
    run, upstream = gh
    result, prompts = run("api", "user", "--jq", ".login")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "someone"
    [seen] = upstream.seen
    assert seen["host"] == "api.github.com"
    assert seen["headers"]["Authorization"] == f"token {TOKEN}"
    assert prompts == []


def test_graphql_query_needs_no_prompt(gh):
    run, _ = gh
    result, prompts = run(
        "api",
        "graphql",
        "-f",
        "query={ viewer { login } }",
        "--jq",
        ".data.viewer.login",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "someone"
    assert prompts == []


def test_declined_write_fails_in_gh_and_never_reaches_github(gh):
    run, upstream = gh
    result, prompts = run("api", "-X", "POST", "repos/o/r/labels", "-f", "name=x")

    assert result.returncode != 0
    assert "declined by user" in result.stderr
    assert upstream.seen == []
    [prompt] = prompts
    assert "POST api.github.com/repos/o/r/labels" in prompt


def test_approved_write_goes_through(gh):
    run, upstream = gh
    result, _ = run(
        "api", "-X", "POST", "repos/o/r/labels", "-f", "name=x", answer=b"once"
    )

    assert result.returncode == 0, result.stderr
    [seen] = upstream.seen
    assert json.loads(seen["body"]) == {"name": "x"}


def test_release_upload_sends_a_content_length(gh, tmp_path):
    """The proxy refuses chunked request bodies, so uploads must have one."""
    run, upstream = gh
    asset = tmp_path / "asset.txt"
    asset.write_bytes(b"payload" * 1000)

    result, prompts = run(
        "release", "upload", "v1", str(asset), "-R", "o/r", answer=b"always"
    )

    assert result.returncode == 0, result.stderr
    # gh looks the repo up with a GraphQL query (a read) first.
    [upload] = [s for s in upstream.seen if s["host"] == "uploads.github.com"]
    assert upload["method"] == "POST"
    assert upload["body"] == asset.read_bytes()
    assert upload["headers"]["Authorization"] == f"token {TOKEN}"
    assert len(prompts) == 1
