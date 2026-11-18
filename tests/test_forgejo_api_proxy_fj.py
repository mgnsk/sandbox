"""End-to-end: the sandbox's fj (upstream forgejo-cli in nix/packages.nix's
wrapper), through forgejo-api-proxy run as a program, to a stand-in for a
Forgejo instance. Fails if fj stops honouring HTTPS_PROXY or SSL_CERT_FILE.

The wrapper has to win over a proxy already in the environment, so the tests
set decoys. FJ_BIN points the tests at another fj than the one on PATH - it
has to be the wrapper.
"""

import json
import os
import shutil
import subprocess

import pytest
from guards import FakeCA, FakePopups, Guard, ProxyInfo, Upstream, base_env, short_dir

FJ = os.environ.get("FJ_BIN") or shutil.which("fj")
pytestmark = pytest.mark.skipif(FJ is None, reason="needs fj")

HOST = "forgejo.example"


def forgejo(h, _body):
    out = json.dumps({"login": "someone", "id": 1}).encode()
    h.send_response(200)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(out)))
    h.end_headers()
    h.wfile.write(out)
    return True


@pytest.fixture
def fj():
    """Run the wrapped fj through a fresh proxy, whose popups get `answer`."""
    d = short_dir()
    ca = FakeCA(d)
    upstream = Upstream(ca)
    upstream.route = forgejo
    popups = FakePopups(d / "popup.sock")
    (d / "forgejo-tokens.json").write_text(json.dumps({HOST: "real-token"}))
    guards = []

    def run(*args, answer=b"no"):
        popups.answer = answer
        popups.requests.clear()
        state = d / f"proxy{len(guards)}"
        state.mkdir()
        env = base_env(
            SSL_CERT_FILE=ca.file,
            SANDBOX_TEST_UPSTREAM=upstream.address,
            SANDBOX_POPUP_SOCKET=popups.path,
            XDG_DATA_HOME=d / "no-host-logins",
        )
        guards.append(
            Guard(
                "forgejo-api-proxy",
                state,
                d / "forgejo-tokens.json",
                env=env,
                ready=state / "proxy.json",
            )
        )
        info = ProxyInfo(state)
        (state / "bundle.pem").write_text(info.ca_pem)
        clean = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("FJ_", "SANDBOX_"))
            and not k.lower().endswith("_proxy")
        }
        result = subprocess.run(
            [FJ, "--host", HOST, "--style", "minimal", *args],
            env={
                **clean,
                "HOME": str(d),
                "XDG_CONFIG_HOME": str(d / "config"),
                "XDG_DATA_HOME": str(d / "data"),
                "XDG_CACHE_HOME": str(d / "cache"),
                "SANDBOX_FJ_PROXY": info.url,
                "SANDBOX_CA_FILE": str(state / "bundle.pem"),
                # Decoys the wrapper has to override.
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "NO_PROXY": "*",
            },
            cwd=d,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return result, popups.texts

    yield run, upstream
    for guard in guards:
        guard.stop()
    popups.close()
    upstream.close()


def test_read_gets_the_real_token(fj):
    run, upstream = fj
    result, prompts = run("whoami")

    assert result.returncode == 0, result.stderr
    assert "someone" in result.stdout
    assert {s["headers"]["Authorization"] for s in upstream.seen} == {
        "token real-token"
    }
    assert prompts == []


def test_declined_write_fails_in_fj_and_never_reaches_forgejo(fj):
    run, upstream = fj
    result, prompts = run("issue", "comment", "o/r#1", "hello")

    assert result.returncode != 0
    assert "declined by user" in result.stderr
    assert not [s for s in upstream.seen if s["method"] not in ("GET", "HEAD")]
    [prompt] = prompts
    assert f"POST {HOST}/api/v1/repos/o/r/issues/1/comments?" in prompt


def test_approved_write_goes_through_with_the_real_token(fj):
    run, upstream = fj
    _, prompts = run("issue", "comment", "o/r#1", "hello", answer=b"once")

    [post] = [s for s in upstream.seen if s["method"] == "POST"]
    assert json.loads(post["body"])["body"] == "hello"
    assert post["headers"]["Authorization"] == "token real-token"
    assert len(prompts) == 1
