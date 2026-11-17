# Security model

What the sandbox contains and how. Read `src/sandbox` (the launcher) itself
for the per-flag reasoning; this file is the threat-model overview.

## Threat model

`sandbox` runs untrusted code (AI agents, arbitrary project builds) with
enough of the host visible to be a usable dev environment. The boundary that
matters: nothing the sandboxed process does may result in **code execution on
the host, or in another project's sandbox**, outside the project directory it
was invoked in.

## Isolation

The primitives (all in `src/sandbox`): a fresh user namespace with the invoking
uid/gid pinned (not namespace-root) and `--disable-userns` to stop nesting;
`--unshare-all`; `--cap-drop ALL`; `--clearenv` with a small re-allowlist; a
fresh pasta network namespace (no host abstract-socket exposure); a seccomp
denylist (`nix/seccomp.py`) trimming kernel attack surface; and guard
proxies for ssh-agent, the Secret Service, and the GitHub and Forgejo APIs so host
credentials are never bound in directly, and one for opening URLs in the host's
browser.

## Writable surface

The only host-backed paths writable from inside are:

- the project directory (`$PWD`); and
- a set of **per-project volumes** under `~/.ide/<volume>/` that map onto
  host-looking paths but are isolated per project and are never the real host
  dir — a file the sandbox writes to one never reaches the host path it shadows,
  and a file the host has there is not visible inside.

Everything else the sandbox needs (`/nix`, configured reference binds, home-manager-generated
config) is mounted **read-only**. Home-manager files, when enabled, reach the
volume as symlinks `sandbox-init` creates from inside the sandbox, into the
read-only store; the host never writes into a volume, since a symlink planted there would redirect the write onto a host
path.

Persistent per-project state (caches, tool config, PATH directories, …) uses
these volumes rather than a shared bind of the host path. Sharing host state
that a host tool later trusts — a `$PATH` directory, or a build cache a
toolchain treats as verified and doesn't re-check — would let sandboxed code
plant something the host or another project runs. The trade is that state isn't
shared across projects (e.g. first builds repopulate their caches), which a
boundary is worth.

## Network: host services only by allowlist

The sandbox gets its own pasta network namespace with ordinary outbound
internet. Ports bound inside are forwarded to the host's `127.0.0.1` (so a
browser on the host reaches OAuth callbacks and dev servers); the other
direction is closed. Host services - on its loopback or on any of its own
addresses - are reachable only for ports listed in `SANDBOX_HOST_PORTS`
(`5037 8080/udp 9000-9010`, tcp by default), read from the host's environment
when `sandbox` starts, and then only at `127.0.0.1:<port>` inside:

- pasta's `-T`/`-U` mirror just those host loopback ports, instead of its
  default of every listener the host has;
- `--map-host-loopback none` and `--map-guest-addr none` remove the addresses
  pasta would otherwise translate to the host;
- the host's global addresses (LAN, tailscale, docker bridges, ...) get
  `prohibit` routes in the namespace before bwrap drops capabilities.

The address list is a snapshot: an address the host gains after the sandbox
started stays reachable until the next start. Other machines on the LAN or
tailnet are not restricted.

A listed port hands the sandbox whatever that service allows to any local
client - an adb server gives a shell on every attached device - so list it
only for the sandbox that needs it.

## GitHub: gh and git run inside, the token stays outside

`gh` and `git` run only inside the sandbox, so hooks, filters and anything
else a repo's `.git/` names run sandboxed. Nothing on the host runs git
against a sandbox-writable repo.

The sandbox's `gh` is patched (`nix/patches/gh-unix-socket.patch`) to send its API
requests as plain HTTP over `GH_HTTP_UNIX_SOCKET`, with `GH_TOKEN` set to a
fixed placeholder. On the other end, `src/gh-api-proxy` runs on the host,
holds the host's real token, and per request:

- drops the client's `Authorization` and adds the real token for the two
  API hosts (`TOKEN_HOSTS`) only;
- forwards REST `GET`/`HEAD` and GraphQL documents containing only queries;
- holds everything else - REST writes, GraphQL mutations and subscriptions,
  anything it can't parse - for a tmux popup (see "Popup answers");
- refuses hosts outside a short allowlist (the API hosts plus the download
  hosts gh gets redirected to), chunked request bodies, and requests with
  more than one `Host` or `Content-Length`.

The gate is the proxy, not `gh`: anything in the sandbox can talk to the
socket, and gets the same treatment. Reads are unprompted and cover whatever
the token can read. Pushes go over ssh through ssh-agent-guard (HTTPS git
only has the placeholder).

## Forgejo: fj runs inside, the token stays outside

The same arrangement for `fj` (forgejo-cli). Its `forgejo-api` crate is
patched (`nix/patches/forgejo-api-unix-socket.patch`) to send requests as plain HTTP
over `FJ_HTTP_UNIX_SOCKET`; the sandbox has no Forgejo token at all. On the
other end, `src/forgejo-api-proxy` (sharing `src/api_proxy.py` with
gh-api-proxy) runs on the host and per request:

- forwards only to instances the host's `fj` is logged in to, over HTTPS,
  dropping the client's `Authorization` and adding that instance's token from
  the host's `keys.json` - re-read every request, so a login on the host
  reaches running sandboxes;
- forwards `GET`/`HEAD`, and holds everything else for a tmux popup.

## Opening URLs: http(s) only, behind a popup

`xdg-open` inside (also at `/usr/bin/xdg-open`) is `src/sandbox-xdg-open`. It
sends the URL to `src/open-url-guard` on the host, which is the gate: anything in
the sandbox can talk to the socket.

The host's `xdg-open` chooses an application from the scheme or file type, so
on sandbox-chosen input it could start any host handler. The guard only passes
it printable-ASCII `http`/`https` URLs with a host and no user info, never
through a shell, and only after a tmux popup (default no) showing the host, the
whole URL and the requesting process. No tmux means no opening.

An approved URL still loads in the real browser with the user's logins, so it
can send a GET to a site they're signed in to or reach a browser exploit, and
the sandbox has no need of the browser to fetch ordinary pages. The popup is
what stands between sandboxed code and that session, so read the host.

## Popup answers

Every popup (`src/guard_popup.py`) takes `y` (this request), `A` (always in this
sandbox) or `N`, the default. No tmux, or a popup that fails, means no.

`A` lasts as long as the guard that was asked: it is only held in that guard's
memory, and each `sandbox` run starts its own guards and kills them on exit.
The next sandbox asks again, and so does another one running on the same
project. It covers one guard only, so `A` on a gh popup doesn't cover ssh or
URLs, and it covers everything in the sandbox, not the process that asked.

So `A` takes the user out of the loop for anything sandboxed code does next:

- **ssh**: any authentication with any key the agent holds, to any host - the
  guard sees neither the destination nor what the session is for, so this isn't
  limited to `git push`.
- **gh** / **fj**: any write the token allows, in any repo it reaches.
- **URLs**: any URL `validate_url` passes, loaded unseen in the logged-in
  browser - the risk described above, with no host left to read.

## Host userland: none

Nothing of the host's `/usr`, `/bin` or `/lib` is bound in. Every program
inside comes from the nix store: the configured package set on `PATH`,
`/bin/sh`, `/bin/env`, `/usr/bin/env` and `/usr/bin/xdg-open` from a small
store directory, and nix-ld at the dynamic loader's path for prebuilt
binaries. From the host's `/etc` only identity and name resolution are bound
(`passwd`, `group`, `hosts`, `resolv.conf`, `nsswitch.conf`, `localtime`);
CA certificates come from the store too.

The launcher itself runs nothing from the host's `PATH` either: bwrap, pasta,
dbus-daemon, ip and the guards' python are store paths in its generated
config. The guards get tmux, gh and xdg-utils from the store first on `PATH`,
the host's after - xdg-open hands approved URLs to the host's browser. The
project root is found by looking for `.git`, not by running git, which would
read a sandbox-writable repo config on the host.

## Writable reference binds

A bind with `writableWhenProject` (e.g. your dotfiles) is read-only reference
in every other project and all of it, `.git` included, read-write when it is
the project. In that mode it is **not a boundary**: if the repo holds
anything the host runs - shell config, a home-manager flake, this sandbox's
own configuration - sandboxed code can rewrite it (or add a git hook,
`core.fsmonitor`, ...) and get host code execution at the next switch or
shell. Only run trusted code in such a project. Untrusted agents and builds
belong in a project directory, where those binds are read-only and
per-project volumes isolate the rest.
