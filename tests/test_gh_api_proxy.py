"""Black-box tests for src/gh-api-proxy (and api_proxy's HTTPS proxy under
it), run as a program: CONNECT and interception, which requests are reads
and which need a popup, forwarding, tokens, refusals and streaming, with
every real host stood in for by one TLS upstream (see guards.py)."""

import json
import socket
import ssl
import stat
from pathlib import Path

import pytest
from guards import (
    BIG,
    FakeCA,
    FakePopups,
    Guard,
    ProxyInfo,
    Upstream,
    base_env,
    https_send,
    proxy_connect,
    raw_request,
    read_response,
    short_dir,
    tls_wrap,
)

API = "api.github.com"
TOKEN = "github_pat_project0123"
HOST_TOKEN = "gho_host0123456"


@pytest.fixture
def world():
    d = short_dir()
    ca = FakeCA(d)
    upstream = Upstream(ca)
    popups = FakePopups(d / "popup.sock")
    yield d, ca, upstream, popups
    popups.close()
    upstream.close()


@pytest.fixture
def start(world):
    """Start a gh-api-proxy; its ProxyInfo and Guard."""
    d, ca, upstream, popups = world
    guards = []

    def start(project_token=TOKEN, host_token=None, upstream_address=None):
        n = len(guards)
        state = d / f"proxy{n}"
        state.mkdir()
        token_file = d / f"github-token{n}"
        if project_token:
            token_file.write_text(project_token + "\n")
        bin_dir = d / f"bin{n}"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(
            f"#!/bin/sh\n[ \"$*\" = 'auth token' ] && [ -n '{host_token or ''}' ] "
            f"&& echo '{host_token}' && exit 0\nexit 1\n"
        )
        gh.chmod(0o755)
        env = base_env(
            PATH=f"{bin_dir}:/nonexistent",
            SSL_CERT_FILE=ca.file,
            SANDBOX_TEST_UPSTREAM=upstream_address or upstream.address,
            SANDBOX_POPUP_SOCKET=popups.path,
        )
        guard = Guard(
            "gh-api-proxy", state, token_file, env=env, ready=state / "proxy.json"
        )
        guards.append(guard)
        return ProxyInfo(state), guard, token_file

    yield start
    for guard in guards:
        guard.stop()


@pytest.fixture
def proxy(start):
    return start()[0]


def request(info, method, host, path, body=b"", headers=(), auth="token placeholder"):
    raw = raw_request(method, host, path, body, headers, auth)
    target = host if ":" in host else f"{host}:443"
    return https_send(info, target, raw)


def graphql(query, **extra):
    return json.dumps({"query": query, **extra}).encode()


def assert_refused(result, status, upstream):
    got, _, body = result
    assert got == status, body
    assert json.loads(body)["message"].startswith("gh-api-proxy:")
    assert upstream.seen == []


# -- forwarding and tokens -------------------------------------------------------


def test_read_is_forwarded_with_the_real_token(proxy, world):
    _, _, upstream, popups = world
    status, _, body = request(proxy, "GET", API, "/user")
    assert status == 200
    assert json.loads(body)["path"] == "/user"
    [seen] = upstream.seen
    assert seen["headers"]["Host"] == API
    assert seen["headers"]["Authorization"] == f"token {TOKEN}"
    assert popups.requests == []


def test_project_token_is_read_per_request_and_wins(start, world):
    _, _, upstream, _ = world
    info, guard, token_file = start(project_token=None, host_token=None)
    status, _, body = request(info, "GET", API, "/user")
    assert status == 403
    assert "sandbox --gh-token" in json.loads(body)["message"]
    assert upstream.seen == []
    # Set later: applies at once.
    token_file.write_text(TOKEN + "\n")
    assert request(info, "GET", API, "/user")[0] == 200
    assert upstream.seen[-1]["headers"]["Authorization"] == f"token {TOKEN}"
    # Malformed: as if there were none - no header smuggled.
    token_file.write_text("bad token\r\nX-Injected: 1\n")
    assert request(info, "GET", API, "/user")[0] == 403
    _, err = guard.stop()
    assert "sandbox --gh-token" in err  # Said at the start, too.


def test_host_gh_token_is_the_fallback(start, world):
    _, _, upstream, _ = world
    info, _, token_file = start(project_token=None, host_token=HOST_TOKEN)
    assert request(info, "GET", API, "/user")[0] == 200
    assert upstream.seen[-1]["headers"]["Authorization"] == f"token {HOST_TOKEN}"
    token_file.write_text(TOKEN + "\n")
    request(info, "GET", API, "/user")
    assert upstream.seen[-1]["headers"]["Authorization"] == f"token {TOKEN}"


def test_hop_by_hop_headers_are_not_forwarded(proxy, world):
    request(
        proxy, "GET", API, "/user", headers=["Connection: keep-alive", "X-Custom: kept"]
    )
    [seen] = world[2].seen
    assert seen["headers"]["X-Custom"] == "kept"
    assert seen["headers"].get("Connection") != "keep-alive"


# -- which requests need a popup ---------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_rest_reads_need_no_popup(proxy, world, method):
    assert request(proxy, method, API, "/repos/o/r/pulls")[0] == 200
    assert world[3].requests == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_rest_writes_are_declined_without_a_yes(proxy, world, method):
    _, _, upstream, popups = world
    assert_refused(
        request(proxy, method, API, "/repos/o/r/labels", b"{}"), 403, upstream
    )
    [asked] = popups.requests
    assert asked["name"] == "gh-api-proxy"
    # The peer is pasta: no process to name.
    assert asked["text"] == (
        f"Allow sandboxed GitHub API write?\n\n{method} {API}/repos/o/r/labels\n"
    )


def test_writes_to_uploads_need_a_popup_too(proxy, world):
    _, _, upstream, popups = world
    result = request(
        proxy, "POST", "uploads.github.com", "/repos/o/r/releases/1/assets", b"x"
    )
    assert_refused(result, 403, upstream)
    assert "POST uploads.github.com/repos/o/r/releases/1/assets" in popups.texts[0]


@pytest.mark.parametrize(
    "query",
    [
        "{ viewer { login } }",
        "query Q { viewer { login } }",
        "query Q($n: Int) { viewer { repositories(first: $n) { totalCount } } }",
        "fragment F on User { login } query { viewer { ...F } }",
        "query A { viewer { login } } query B { rateLimit { remaining } }",
    ],
)
def test_graphql_queries_need_no_popup(proxy, world, query):
    _, _, upstream, popups = world
    body = graphql(query)
    assert request(proxy, "POST", API, "/graphql", body)[0] == 200
    assert upstream.seen[0]["body"] == body
    assert popups.requests == []


@pytest.mark.parametrize(
    "query",
    [
        'mutation { addStar(input: {starrableId: "x"}) { clientMutationId } }',
        "subscription { viewer { login } }",
        # A mutation anywhere in the document counts, whichever operation
        # operationName selects.
        "query A { viewer { login } } mutation B { addStar(input: {}) { clientMutationId } }",
    ],
)
def test_graphql_mutations_and_subscriptions_need_a_popup(proxy, world, query):
    result = request(proxy, "POST", API, "/graphql", graphql(query, operationName="A"))
    assert_refused(result, 403, world[2])
    assert len(world[3].requests) == 1


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"\xff\xfe",
        b"[]",
        json.dumps([{"query": "{ viewer { login } }"}]).encode(),  # Batched.
        json.dumps({"variables": {}}).encode(),  # No query.
        json.dumps({"query": 1}).encode(),
        graphql("{ viewer { login }"),  # Syntax error.
        graphql("fragment F on User { login }"),  # No operation.
        graphql("{" * 20000 + "}" * 20000),  # Too deep to parse.
    ],
    ids=["empty", "not-json", "not-utf8", "empty-list", "batched", "no-query",
         "query-not-string", "syntax-error", "no-operation", "too-deep"],
)  # fmt: skip
def test_unparseable_graphql_needs_a_popup(proxy, world, body):
    assert_refused(request(proxy, "POST", API, "/graphql", body), 403, world[2])
    assert "(not a GraphQL request this proxy understands)" in world[3].texts[0]


def test_graphql_over_get_needs_a_popup(proxy, world):
    assert_refused(request(proxy, "GET", API, "/graphql"), 403, world[2])
    assert world[3].requests


def test_graphql_popup_lists_operations_and_variables(proxy, world):
    body = graphql(
        "mutation M($id: ID!) { addStar(input: {starrableId: $id}) { clientMutationId } }",
        variables={"id": "R_1"},
    )
    request(proxy, "POST", API, "/graphql", body)
    [text] = world[3].texts
    assert "POST api.github.com/graphql" in text
    assert "mutation M: addStar" in text
    assert '"id": "R_1"' in text


def test_graphql_popup_text_in_full(proxy, world):
    """Operations with their top-level fields (not aliases), and variables
    as sent: key order kept, indented, non-ASCII as it is."""
    variables = {
        "z": {"nested": [1, -2, 1.5, True, False, None], "empty": {}, "none": []},
        "a": 'quote " backslash \\ newline \n tab \t ctl \x01 日本',
    }
    query = (
        "query Q { viewer { login } } "
        "mutation { first: addStar(input: {}) { clientMutationId } "
        "...F removeStar(input: {}) { clientMutationId } } "
        "fragment F on Mutation { x }"
    )
    request(proxy, "POST", API, "/graphql", graphql(query, variables=variables))
    [text] = world[3].texts
    dumped = json.dumps(variables, indent=2, ensure_ascii=False)
    assert text == (
        "Allow sandboxed GitHub API write?\n\n"
        "POST api.github.com/graphql\n\n"
        "query Q: viewer\n"
        "mutation (anonymous): addStar, removeStar\n\n"
        f"variables:\n{dumped}\n"
    )


@pytest.mark.parametrize("variables", [None, {}, [], 0, 0.0, "", False])
def test_empty_graphql_variables_are_not_shown(proxy, world, variables):
    query = "mutation { addStar(input: {}) { clientMutationId } }"
    request(proxy, "POST", API, "/graphql", graphql(query, variables=variables))
    assert "variables:" not in world[3].texts[0]


def test_popup_text_is_cleaned_but_not_truncated(proxy, world):
    path = "/repos/o/r/\x1b[31m/" + "x" * 5000
    request(proxy, "DELETE", API, path)
    [text] = world[3].texts
    assert "\x1b" not in text
    assert "?[31m/" + "x" * 5000 in text


# -- approvals ---------------------------------------------------------------------


def test_write_approved_once_is_forwarded_and_the_next_one_asks_again(proxy, world):
    _, _, upstream, popups = world
    popups.answer = b"once"
    for _ in range(2):
        status, _, _ = request(proxy, "POST", API, "/repos/o/r/labels", b'{"name":"x"}')
        assert status == 200
    assert [s["body"] for s in upstream.seen] == [b'{"name":"x"}'] * 2
    assert upstream.seen[0]["headers"]["Authorization"] == f"token {TOKEN}"
    assert len(popups.requests) == 2


def test_always_covers_later_writes_until_the_proxy_ends(start, world):
    _, _, upstream, popups = world
    popups.answer = b"always"
    info, _, _ = start()
    for label in ("x", "y"):
        assert request(info, "DELETE", API, f"/repos/o/r/labels/{label}")[0] == 200
    assert len(popups.requests) == 1
    # A new sandbox starts a new proxy, which asks again.
    info, _, _ = start()
    assert request(info, "DELETE", API, "/repos/o/r/labels/z")[0] == 200
    assert len(popups.requests) == 2
    assert len(upstream.seen) == 3


@pytest.mark.parametrize("answer", [b"no", b"", b"garbage", b"once" * 100])
def test_anything_but_once_or_always_is_no(proxy, world, answer):
    world[3].answer = answer
    assert request(proxy, "DELETE", API, "/repos/o/r/labels/x")[0] == 403


def test_without_a_popup_socket_writes_are_declined(world, start):
    world[3].close()
    info, _, _ = start()
    assert_refused(request(info, "DELETE", API, "/repos/o/r/labels/x"), 403, world[2])


# -- hosts ----------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["api.github.com", "uploads.github.com"])
def test_token_hosts_are_intercepted(proxy, world, host):
    request(proxy, "GET", host, "/x")
    assert world[2].seen[0]["headers"]["Authorization"] == f"token {TOKEN}"


@pytest.mark.parametrize(
    "host",
    ["github.com", "codeload.github.com", "objects.githubusercontent.com",
     "productionresultssa0.blob.core.windows.net"],
)  # fmt: skip
def test_download_hosts_are_tunneled_unread(proxy, world, host):
    """The client's TLS goes to the real host itself: its own Authorization
    arrives, and no token is added."""
    _, ca, upstream, _ = world
    sock, head = proxy_connect(proxy, f"{host}:443")
    assert " 200 " in head.split("\r\n", 1)[0], head
    ctx = ssl.create_default_context(cafile=ca.file)
    ctx.check_hostname = False  # The stand-in's certificate has fewer names.
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        tls.sendall(raw_request("GET", host, "/asset"))
        status, _, _ = read_response(tls, "GET")
    assert status == 200
    [seen] = upstream.seen
    assert seen["headers"]["Authorization"] == "token placeholder"


@pytest.mark.parametrize(
    "target",
    ["example.com:443", "githubusercontent.com.example.com:443",
     "api.github.com:8443", "github.com:22"],
)  # fmt: skip
def test_other_hosts_are_intercepted_and_refused(proxy, world, target):
    host = target.removesuffix(":443")
    result = https_send(proxy, target, raw_request("GET", host, "/"))
    assert_refused(result, 403, world[2])


# -- the proxy itself ----------------------------------------------------------------


@pytest.mark.parametrize("auth", [False, "Basic c2FuZGJveDp3cm9uZw=="])
def test_connect_needs_the_secret(proxy, world, auth):
    sock, head = proxy_connect(proxy, "api.github.com:443", auth=auth)
    sock.close()
    assert head.startswith("HTTP/1.1 407 ")
    assert "Proxy-Authenticate: Basic" in head
    assert world[2].seen == []


@pytest.mark.parametrize(
    "target",
    ["api.github.com", "a b:443", "[::1]:443", "x:0", "x:70000", "api.github.com.:443"],
)
def test_bad_connect_target_is_refused(proxy, target):
    sock, head = proxy_connect(proxy, target)
    sock.close()
    assert head.startswith("HTTP/1.1 400 ")


def test_plain_http_proxying_is_refused(proxy):
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=10) as sock:
        sock.sendall(
            b"GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        )
        assert sock.recv(64).startswith(b"HTTP/1.1 405 ")


def test_announces_its_ca_port_and_secret(start):
    info, guard, _ = start()
    proxy_json = Path(guard.proc.args[-2]) / "proxy.json"
    assert stat.S_IMODE(proxy_json.stat().st_mode) & 0o077 == 0
    assert info.ca_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert len(info.secret) >= 32


def test_each_proxy_has_its_own_ca_and_secret(start):
    a, b = start()[0], start()[0]
    assert a.ca_pem != b.ca_pem
    assert a.secret != b.secret
    sock, _ = proxy_connect(a, "api.github.com:443")
    with pytest.raises(ssl.SSLCertVerificationError):
        tls_wrap(sock, b.ca_pem, "api.github.com")
    sock.close()


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        # Another host than the CONNECT target.
        (b"GET /asset HTTP/1.1\r\nHost: objects.githubusercontent.com\r\n\r\n", 421),
        (b"GET /user HTTP/1.1\r\nHost: api.github.com\r\nHost: example.com\r\n\r\n", 421),
        (b"GET /user HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n", 400),
        (b"GET /user HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: x\r\n\r\n", 400),
        (b"POST /repos/o/r/labels HTTP/1.1\r\nHost: api.github.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 411),
        (b"GET https://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\n\r\n", 400),
    ],
    ids=["other-host", "two-hosts", "two-lengths", "bad-length", "chunked", "absolute-form"],
)  # fmt: skip
def test_malformed_requests_are_refused(proxy, world, raw, status):
    assert_refused(https_send(proxy, "api.github.com:443", raw), status, world[2])


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (b"PROPFIND /user HTTP/1.1\r\nHost: api.github.com\r\n\r\n", 501),
        (b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n", 501),
        (b"GET /user HTTP/2.0\r\nHost: api.github.com\r\n\r\n", 505),
        (b"GET /user HTTP/x\r\nHost: api.github.com\r\n\r\n", 400),
        (b"GET /user HTTP/1.1\r\nHost: api.github.com\r\n" + b"X-A: 1\r\n" * 100 + b"\r\n", 431),
        (b"GET /user HTTP/1.1\r\nHost: api.github.com\r\nX-A: " + b"a" * 70000 + b"\r\n\r\n", 431),
    ],
    ids=["unknown-method", "connect-inside", "http2", "bad-version",
         "too-many-headers", "header-too-long"],
)  # fmt: skip
def test_requests_it_cannot_read_are_refused(proxy, world, raw, status):
    """Refused by status alone: the body is http.server's own page in the
    Python implementation."""
    assert https_send(proxy, "api.github.com:443", raw)[0] == status
    assert world[2].seen == []


def test_a_network_path_target_is_a_plain_path(proxy, world):
    """//x is /x, as http.server reads it - never another host."""
    status, _, _ = https_send(
        proxy, "api.github.com:443", raw_request("GET", API, "//evil.example/user")
    )
    assert status == 200
    assert world[2].seen[0]["path"] == "/evil.example/user"


def test_oversized_graphql_body_is_refused(proxy, world):
    # Refused on its Content-Length, before the body is sent.
    raw = (
        f"POST /graphql HTTP/1.1\r\nHost: {API}\r\n"
        f"Content-Length: {10 * 1024 * 1024 + 1}\r\n\r\n"
    ).encode()
    assert_refused(https_send(proxy, f"{API}:443", raw), 413, world[2])


def test_unreachable_upstream_is_a_502(start):
    info, _, _ = start(upstream_address="127.0.0.1:1")
    status, _, body = request(info, "GET", API, "/user")
    assert status == 502
    assert "upstream error" in json.loads(body)["message"]


def test_untrusted_upstream_is_a_502(start, world):
    """Upstream's certificate is checked like the real host's would be."""
    other = Upstream(FakeCA(short_dir()))
    try:
        info, _, _ = start(upstream_address=other.address)
        assert request(info, "GET", API, "/user")[0] == 502
        assert other.seen == []
    finally:
        other.close()


# -- responses ---------------------------------------------------------------------


def test_large_chunked_response_is_relayed_in_full(proxy):
    status, _, body = request(proxy, "GET", API, "/big")
    assert status == 200
    assert body == BIG


def test_redirect_is_passed_back_to_the_client(proxy):
    status, headers, _ = request(proxy, "GET", API, "/redirect")
    assert status == 302
    assert headers["Location"] == "https://objects.githubusercontent.com/asset"


def test_head_has_headers_but_no_body(proxy):
    status, headers, body = request(proxy, "HEAD", API, "/user")
    assert status == 200
    assert int(headers["Content-Length"]) > 0
    assert body == b""


def test_request_body_is_streamed_upstream(proxy, world):
    _, _, upstream, popups = world
    popups.answer = b"once"
    payload = bytes(range(256)) * 4096
    status, _, _ = request(
        proxy, "POST", "uploads.github.com", "/repos/o/r/releases/1/assets", payload
    )
    assert status == 200
    [seen] = upstream.seen
    assert seen["body"] == payload
    assert seen["headers"]["Authorization"] == f"token {TOKEN}"
