"""Tests for bin/gh-api-proxy's request classification: which requests are
reads (forwarded) and which are writes (need approval). No sockets."""

import json

import pytest
from conftest import load_module

proxy = load_module("gh-api-proxy")

API = "api.github.com"


def graphql(query, **extra):
    return json.dumps({"query": query, **extra}).encode()


def is_read(method, host, path, body=None):
    return proxy.describe_write(method, host, path, body) is None


# -- REST --------------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_rest_reads(method):
    assert is_read(method, API, "/repos/o/r/pulls")


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_rest_writes(method):
    assert not is_read(method, API, "/repos/o/r/labels")


def test_writes_to_other_hosts_need_approval_too():
    assert not is_read("POST", "uploads.github.com", "/repos/o/r/releases/1/assets")


def test_rest_write_description_names_the_request():
    assert proxy.describe_write("DELETE", API, "/repos/o/r/labels/x") == (
        "DELETE api.github.com/repos/o/r/labels/x"
    )


# -- GraphQL -----------------------------------------------------------------


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
def test_graphql_queries_are_reads(query):
    assert is_read("POST", API, "/graphql", graphql(query))


@pytest.mark.parametrize(
    "query",
    [
        "mutation { addStar(input: {starrableId: \"x\"}) { clientMutationId } }",
        "subscription { viewer { login } }",
        # A mutation anywhere in the document counts, whichever operation
        # operationName selects.
        "query A { viewer { login } } mutation B { addStar(input: {}) { clientMutationId } }",
    ],
)
def test_graphql_mutations_and_subscriptions_are_writes(query):
    assert not is_read("POST", API, "/graphql", graphql(query, operationName="A"))


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
    ids=[
        "empty",
        "not-json",
        "not-utf8",
        "empty-list",
        "batched",
        "no-query",
        "query-not-string",
        "syntax-error",
        "no-operation",
        "too-deep",
    ],
)
def test_unparseable_graphql_needs_approval(body):
    assert not is_read("POST", API, "/graphql", body)


def test_graphql_over_get_needs_approval():
    assert not is_read("GET", API, "/graphql", b"")


def test_graphql_description_lists_operations_and_variables():
    description = proxy.describe_write(
        "POST",
        API,
        "/graphql",
        graphql(
            "mutation M($id: ID!) { addStar(input: {starrableId: $id}) { clientMutationId } }",
            variables={"id": "R_1"},
        ),
    )
    assert "mutation M: addStar" in description
    assert '"id": "R_1"' in description


# -- hosts ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "api.github.com",
        "uploads.github.com",
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "productionresultssa0.blob.core.windows.net",
    ],
)
def test_allowed_hosts(host):
    assert proxy.host_allowed(host)


@pytest.mark.parametrize(
    "host",
    [
        "",
        "example.com",
        "githubusercontent.com.example.com",
        "api.github.com.",
        "API.GITHUB.COM",
        "api.github.com:8443",
        "api.github.com\r\nx",
    ],
)
def test_other_hosts_are_refused(host):
    assert not proxy.host_allowed(host)


def test_only_api_hosts_get_the_token():
    assert {"api.github.com", "uploads.github.com"} == proxy.TOKEN_HOSTS


# -- clean() -----------------------------------------------------------------


def test_clean_strips_control_characters_but_keeps_lines():
    assert proxy.clean("a\x1b[31mb\nc\td") == "a?[31mb\nc?d"


def test_clean_does_not_truncate():
    assert proxy.clean("x" * 10000) == "x" * 10000
