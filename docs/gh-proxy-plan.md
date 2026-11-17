# Plan: run gh and git inside the sandbox, gate GitHub API requests on the host

Status: done. gh-guard and gh-client are removed; sandbox-security.md describes the result. Kept as the design record.

## Why

gh-guard runs the host's real `gh` inside the sandbox-writable project
directory. Several subcommands (`pr create`, `pr checkout`, `pr merge`,
`repo sync`, ...) run `git` there, and git runs commands that the repo's own
config and attributes name - on the host. The overrides in gh-guard block
the known routes but leave `.git/info/attributes` (documented in
sandbox-security.md) and anything git adds later. gh-guard also needs an
ever-growing argv allowlist and blocklist (`gh api` flag walker, token-revealing
flags, file-writing flags) to decide what's a read.

The fix is to stop running gh and git on the host at all:

- `gh` and `git` run only inside the sandbox.
- The real token stays on the host, in a proxy that `gh`'s API requests go
  through. The proxy adds the token and decides per HTTP request: reads pass,
  writes get the popup.

## Design

```
sandbox                                   host
-------                                   ----
gh (patched, GH_TOKEN=placeholder)
  -- plain HTTP over unix socket -->  gh-api-proxy
                                        - drops client Authorization
                                        - read? forward : popup
                                        - adds real token (API hosts only)
                                        -- HTTPS --> api.github.com, uploads.github.com
git (ssh remotes) -- ssh-agent-guard (sign popup, as today) --> github.com
```

### 1. gh patch (Nix overlay)

gh's HTTP library (go-gh v2.17.0, `pkg/api/http_client.go`) already supports
a unix socket: `newUnixDomainSocketRoundTripper` dials the socket for both
plain and TLS connections and sends the request as plain HTTP, with the real
host in `Host`. gh 2.103.0's own API client (`api/http_client.go`,
`NewHTTPClient`) never sets `UnixDomainSocket`, though - only telemetry
reads `http_unix_socket`.

Patch `api/http_client.go`, in the `ghAPI.ClientOptions` literal in
`NewHTTPClient`:

```go
UnixDomainSocket: os.Getenv("GH_HTTP_UNIX_SOCKET"),
```

plus the `"os"` import. Every client gh builds through `NewHTTPClient` (API,
token refresher, plain) picks it up; with the variable unset nothing changes,
so the host gh behaves exactly as before. `NewExternalHTTPClient` (non-GitHub
hosts) stays direct.

Overlay: `gh.overrideAttrs (old: { patches = (old.patches or [ ]) ++ [ ./gh-unix-socket.patch ]; })`.
No go.mod change, so `vendorHash` stays. The patch has to be rechecked when gh
is bumped - a test (below) fails if the env var stops having an effect.

The client-side setting is not a security control: if something in the
sandbox unsets the variable, gh talks to GitHub directly with the placeholder
token and simply gets 401s.

### 2. gh-api-proxy (new, host side, replaces gh-guard)

Python, threaded `http.server` on a unix socket that bin/sandbox binds into
the sandbox, one instance per sandbox, like the guards today.

- **Upstream hosts:** allowlist. `api.github.com` and `uploads.github.com` get
  the real token; redirect targets gh follows through the same transport
  (`objects.githubusercontent.com`, `codeload.github.com`, ...) are forwarded
  without one. Anything else: 403.
- **Authorization:** always drop the client's header. Add `Authorization:
  token <real>` for the token hosts only.
- **Token:** read once at startup with the host's `gh auth token`, held in
  memory, never written to disk or sent into the sandbox.
- **Classification:**
  - REST: `GET`/`HEAD` forward; anything else -> popup.
  - `POST /graphql`: buffer the body (capped, e.g. 10 MB) and parse it with
    `graphql-core` (python3Packages.graphql-core 3.2.7). Any `mutation` or
    `subscription` operation in the document -> popup; queries only -> forward.
    Parse error, unknown shape, batched array, or anything unexpected -> popup.
- **Popup:** shows method, host, path, and for GraphQL the operation type,
  name, top-level fields, and variables (non-printables stripped, as
  `clean()` does today). Choices:
  - `y`: this request;
  - `a`: all writes from this process (the gh pid from SO_PEERCRED) until it
    exits - one `gh pr create --reviewer x --label y` makes several mutations;
  - `N` (default): 403 back to gh.
- **Streaming:** request bodies other than GraphQL (release uploads) and all
  responses are streamed, not buffered. Content-Length bodies only;
  chunked request bodies are refused (gh sends lengths for uploads - to be
  checked).
- **Limits:** header size and count via `http.server`'s defaults, request
  timeouts, one thread per connection (gh disables keep-alive on the socket
  transport).

### 3. bin/sandbox

- Start gh-api-proxy instead of gh-guard; bind its socket to
  `$XDG_RUNTIME_DIR/gh-api.sock`; `--setenv GH_HTTP_UNIX_SOCKET` to it.
- `--setenv GH_TOKEN` to a placeholder, so gh considers itself logged in.
- Drop the gh-client bind over the store path; the sandbox runs the real
  (patched) gh from the profile.
- Set `git_protocol: ssh` in the sandbox gh's config so `gh pr checkout` of
  a PR without a matching remote fetches over ssh, through ssh-agent-guard.

### 4. Removed

- `bin/gh-guard`, `bin/gh-client` and their tests, including the argv
  allowlist, `gh api` flag walker, token-reveal blocks and git-config
  overrides. None of it applies once nothing runs gh or git on the host.
- The "Host `gh` and the project's `.git/`" section and its known gap in
  sandbox-security.md, replaced by a section on the proxy.

## What changes for you

- `gh pr create`, `gh pr checkout`, `--fill` and everything else work as
  normal inside the sandbox; git and hooks run sandboxed.
- Popups describe API calls (`POST /graphql mutation createPullRequest`)
  rather than gh command lines; `a` keeps it to one popup per command.
- Pushes go over ssh with the existing ssh-agent-guard popup. HTTPS git to
  github.com doesn't authenticate (placeholder token); public HTTPS fetches
  still work.
- Unprompted reads stay as broad as today: anything the token can read.

## Tests

- **Proxy, unit:** classification table (REST methods; GraphQL query,
  mutation, mixed document, `operationName` selection, malformed, batched),
  Authorization stripping and injection per host, host allowlist, body cap,
  chunked refusal, popup decline -> 403 with no upstream request.
- **Proxy, integration:** a fake upstream over loopback HTTP (proxy upstream
  made injectable), with the patched gh as the client: `gh api user`,
  `gh api -X POST ...` declined and approved, `gh pr list` (GraphQL query, no
  popup).
- **Patch:** with `GH_HTTP_UNIX_SOCKET` set to a test socket, `gh api user`
  arrives there as plain HTTP with `Host: api.github.com` - fails if a gh
  bump drops or breaks the patch.
- **sandbox:** existing static tests updated for the new binds and env.

## Order

1. Patch + overlay, and the patch test. `home-manager switch`.
2. gh-api-proxy with unit and integration tests.
3. bin/sandbox switch-over; gh-guard and gh-client kept one release behind
   a flag for fallback, then removed with their tests.
4. sandbox-security.md rewrite.

## Open questions

- Variables in the popup: full values can be long (PR bodies). Show them in
  full, scrollable (`less` in the popup), rather than truncated - truncation
  is what clean() avoids today for the same reason.
- Whether any gh path still uses a client not built by `NewHTTPClient` for
  API hosts (would bypass the socket and fail with the placeholder, not leak
  anything) - found by the integration test.
- `gh auth status` and token refresh with a placeholder `GH_TOKEN`: expected
  to work through the proxy, to confirm.
