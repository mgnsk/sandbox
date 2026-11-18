"""Black-box tests for src/forgejo-api-proxy, run as a program: which hosts
and tokens it takes from the host fj's keys.json and the project's tokens
file, and what it forwards, with a stand-in for every Forgejo instance. The
shared mechanics (refusals, streaming) are covered through gh-api-proxy's
tests."""

import json

import pytest
from guards import (
    FakeCA,
    FakePopups,
    Guard,
    ProxyInfo,
    Upstream,
    base_env,
    https_send,
    proxy_connect,
    raw_request,
    short_dir,
    tls_wrap,
)

HOST = "forgejo.example"
NAMES = (HOST, "a.example", "b.example", "c.example")


@pytest.fixture
def world():
    d = short_dir()
    ca = FakeCA(d)
    upstream = Upstream(ca, NAMES)
    popups = FakePopups(d / "popup.sock")
    yield d, upstream, popups, ca
    popups.close()
    upstream.close()


@pytest.fixture
def start(world):
    """Start a forgejo-api-proxy with these host fj logins and project
    tokens; its ProxyInfo and the two files, which it reads per request."""
    d, upstream, popups, ca = world
    guards = []

    def start(hosts=None, project=None, xdg=True):
        n = len(guards)
        state = d / f"proxy{n}"
        state.mkdir()
        data = d / f"data{n}"
        keys = data / "forgejo-cli/keys.json"
        keys.parent.mkdir(parents=True)
        if hosts is not None:
            write_keys(keys, hosts)
        project_file = d / f"forgejo-tokens{n}.json"
        if project is not None:
            project_file.write_text(json.dumps(project))
        env = base_env(
            SSL_CERT_FILE=ca.file,
            SANDBOX_TEST_UPSTREAM=upstream.address,
            SANDBOX_POPUP_SOCKET=popups.path,
        )
        if xdg:
            env["XDG_DATA_HOME"] = str(data)
        else:
            home = d / f"home{n}"
            (home / ".local").mkdir(parents=True)
            (home / ".local/share").symlink_to(data)
            env["HOME"] = str(home)
        guards.append(
            Guard(
                "forgejo-api-proxy",
                state,
                project_file,
                env=env,
                ready=state / "proxy.json",
            )
        )
        return ProxyInfo(state), keys, project_file

    yield start
    for guard in guards:
        guard.stop()


def write_keys(path, hosts):
    path.write_text(json.dumps({"hosts": hosts, "aliases": {}, "default_ssh": []}))


def app(token):
    return {"type": "Application", "token": token}


def request(info, method, host, path, body=b""):
    target = host if ":" in host else f"{host}:443"
    status, _, out = https_send(info, target, raw_request(method, host, path, body))
    return status, out


def test_read_gets_the_hosts_token_without_a_prompt(start, world):
    _, upstream, popups, _ = world
    info, _, _ = start({HOST: app("real")})
    status, _ = request(info, "GET", HOST, "/api/v1/user")
    assert status == 200
    [seen] = upstream.seen
    assert seen["headers"]["Authorization"] == "token real"
    assert seen["headers"]["Host"] == HOST
    assert popups.requests == []


def test_tokens_come_from_every_login_type(start, world):
    _, upstream, _, _ = world
    info, _, _ = start(
        {
            "a.example": app("app"),
            "b.example:3000/forgejo": {
                "type": "OAuth",
                "token": "oauth",
                "refresh_token": "r",
                "expires_at": "2030-01-01T00:00:00Z",
            },
        }
    )
    assert request(info, "GET", "a.example", "/x")[0] == 200
    # A host with a port keeps it.
    assert request(info, "GET", "b.example:3000", "/x")[0] == 200
    assert [
        (s["headers"]["Host"], s["headers"]["Authorization"]) for s in upstream.seen
    ] == [
        ("a.example", "token app"),
        ("b.example:3000", "token oauth"),
    ]


@pytest.mark.parametrize(
    "content",
    [None, "", "not json", "[]", '{"hosts": []}', '{"hosts": {"a.example": 1}}'],
)
def test_missing_or_odd_keys_file_means_no_hosts(start, world, content):
    info, keys, _ = start()
    if content is not None:
        keys.write_text(content)
    assert request(info, "GET", "a.example", "/x")[0] == 403
    assert world[1].seen == []


def test_keys_file_is_under_home_without_xdg_data_home(start):
    info, _, _ = start({HOST: app("real")}, xdg=False)
    assert request(info, "GET", HOST, "/x")[0] == 200


def test_project_tokens_win_and_keep_only_well_formed_entries(start, world):
    _, upstream, _, _ = world
    info, _, project = start({HOST: app("host-token")})
    project.write_text(
        json.dumps({"Forgejo.Example": "project1", "a.example": "bad token", "c": 1})
    )
    assert request(info, "GET", HOST, "/x")[0] == 200
    assert upstream.seen[-1]["headers"]["Authorization"] == "token project1"
    assert request(info, "GET", "a.example", "/x")[0] == 403
    project.write_text("[]")
    assert request(info, "GET", HOST, "/x")[0] == 200
    assert upstream.seen[-1]["headers"]["Authorization"] == "token host-token"


@pytest.mark.parametrize("host", ["other.example", f"{HOST}:3000"])
def test_hosts_not_logged_in_are_refused_with_how_to_log_in(start, world, host):
    info, _, _ = start({HOST: app("real")})
    status, body = request(info, "GET", host, "/api/v1/user")
    assert status == 403
    message = json.loads(body)["message"]
    assert message.startswith("forgejo-api-proxy:")
    assert f"sandbox --fj-token {host}" in message
    assert f"fj --host {host} auth add-token" in message
    assert world[1].seen == []


def test_nothing_is_tunneled_unread(start):
    """Every host is intercepted, so one not logged in gets the refusal
    above rather than a tunnel to the host's own services."""
    info, _, _ = start({HOST: app("real")})
    sock, head = proxy_connect(info, "127.0.0.1:22")
    assert " 200 " in head.split("\r\n", 1)[0]
    # The proxy's own certificate: intercepted.
    tls_wrap(sock, info.ca_pem, "127.0.0.1").close()


def test_a_login_on_the_host_applies_without_a_restart(start):
    info, keys, project = start({})
    assert request(info, "GET", HOST, "/x")[0] == 403
    write_keys(keys, {HOST: app("real")})
    assert request(info, "GET", HOST, "/x")[0] == 200
    keys.unlink()
    project.write_text(json.dumps({HOST: "project1"}))
    assert request(info, "GET", HOST, "/x")[0] == 200


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_declined_write_never_reaches_upstream(start, world, method):
    _, upstream, popups, _ = world
    info, _, _ = start({HOST: app("real")})
    status, body = request(
        info, method, HOST, "/api/v1/repos/o/r/issues", b'{"title":"x"}'
    )
    assert status == 403
    assert "declined by user" in json.loads(body)["message"]
    assert upstream.seen == []
    [asked] = popups.requests
    assert asked["name"] == "forgejo-api-proxy"
    assert asked["text"] == (
        f"Allow sandboxed Forgejo API write?\n\n{method} {HOST}/api/v1/repos/o/r/issues\n"
    )


def test_approved_write_goes_through_with_its_body(start, world):
    _, upstream, popups, _ = world
    popups.answer = b"once"
    info, _, _ = start({HOST: app("real")})
    status, _ = request(
        info, "POST", HOST, "/api/v1/repos/o/r/issues", b'{"title":"x"}'
    )
    assert status == 200
    [seen] = upstream.seen
    assert (seen["body"], seen["headers"]["Authorization"]) == (
        b'{"title":"x"}',
        "token real",
    )
