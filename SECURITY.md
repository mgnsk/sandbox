# Security model

What the sandbox contains and how. Read `internal/launcher` (the launcher)
itself for the per-flag reasoning; this file is the threat-model overview.
The launcher, init and the guards are subcommands of one Go binary,
`sandbox-bin` (`cmd/sandbox-bin`).

## Threat model

`sandbox` runs untrusted code (AI agents, arbitrary project builds) with
enough of the host visible to be a usable dev environment. The boundary that
matters: nothing the sandboxed process does may result in **code execution on
the host, or in another project's sandbox**, outside the project directory it
was invoked in.

## Isolation

The primitives (all in `internal/launcher`): a fresh user namespace with the invoking
uid/gid pinned (not namespace-root) and `--disable-userns` to stop nesting;
`--unshare-all`; `--cap-drop ALL`; `--clearenv` with a small re-allowlist; a
fresh pasta network namespace (no host abstract-socket exposure); a seccomp
denylist (`internal/seccomp`) trimming kernel attack surface; and guard
proxies for ssh-agent, the Secret Service, and the GitHub, Forgejo and Claude
APIs so host credentials are never bound in directly, and one for opening URLs in the host's
browser.

## Writable surface

The only host-backed paths writable from inside are:

- the project directory: the top level of the git work tree `$PWD` is in, or
  `$PWD` itself outside one; and
- a **per-project home volume**, mounted over `$HOME`: the directory
  `<state dir>/<volume><$HOME>` on the host, where the state dir is
  `stateDir` (default `$XDG_DATA_HOME/sandbox`, i.e.
  `~/.local/share/sandbox`) and `<volume>` is the project path made flat plus
  a hash. It looks like the host home but is never the real one — a file the
  sandbox writes there never reaches the host path it shadows, and a file the
  host has there is not visible inside. The project's secrets (tokens, keys,
  Secret Service data, approvals) sit next to it in `<state dir>/<volume>/`,
  outside the mount, out of the sandbox's reach.

Everything else the sandbox needs (`/nix`, configured reference binds, home-manager-generated
config) is mounted **read-only**. Home-manager files, when enabled, reach the
volume as symlinks `sandbox-bin init` creates from inside the sandbox, into the
read-only store; the host never writes into a volume, since a symlink planted there would redirect the write onto a host
path.

Persistent per-project state (caches, tool config, PATH directories, …) uses
this volume rather than a shared bind of the host path. Sharing host state
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

The GitHub and Forgejo guards' proxies are mapped the same way, on ports
picked at start; they take only requests carrying their per-launch secret.

A listed port hands the sandbox whatever that service allows to any local
client - an adb server gives a shell on every attached device - so list it
only for the sandbox that needs it.

One host service is reachable without listing: a DNS resolver on the host's
loopback (systemd-resolved's `127.0.0.53`, a local dnsmasq or unbound), when
it is the first `nameserver` in the host's `/etc/resolv.conf`. pasta's
`--dns-forward` maps `169.254.1.53` inside to that one resolver, ports 53 and
853 only, and the sandbox's `resolv.conf` points there. Without it the
sandbox has no DNS on such hosts. What it exposes is the resolver itself:
its parser as attack surface, the names it knows that public DNS doesn't
(LAN, VPN and mDNS names; the addresses themselves were reachable anyway),
and its cache, which shows by timing what the host resolved recently. DNS as
an exfiltration channel adds nothing to the ordinary outbound internet the
sandbox has.

## GitHub: gh and git run inside, the token stays outside

`gh` and `git` run only inside the sandbox, so hooks, filters and anything
else a repo's `.git/` names run sandboxed. Nothing on the host runs git
against a sandbox-writable repo.

The sandbox's `gh` is upstream gh in a wrapper (`nix/packages.nix`) that sets
`HTTPS_PROXY` to gh-api-proxy (`internal/ghproxy`) and `SSL_CERT_FILE` to a bundle with that
proxy's CA, with `GH_TOKEN` set to a fixed placeholder. The proxy runs on the
host and holds the real token: the project's, if `sandbox --gh-token` set one
(`github-token` in the volume dir, mode 0600, re-read every request), else the
host gh's, read at start. It listens on a free port of the host's
loopback, which pasta's `-T` maps into the sandbox, and only takes a `CONNECT`
carrying a random per-launch secret (in the proxy URL inside, sent as Basic
`Proxy-Authorization`), since anything on the host's loopback can reach the
port.

For the two API hosts (`TOKEN_HOSTS`), it answers the TLS handshake itself,
with a certificate from a CA it generated at startup. The CA's key exists only
in the proxy's memory and dies with it; its certificate is trusted only by the
wrapped gh and fj (`SANDBOX_CA_FILE`), never sandbox-wide. Inside the tunnel,
per request, it:

- requires `Host` to be the `CONNECT` target;
- drops the client's `Authorization` and adds the real token;
- forwards REST `GET`/`HEAD` and GraphQL documents containing only queries;
- holds everything else - REST writes, GraphQL mutations and subscriptions,
  anything it can't parse - for a popup (see "Popup answers");
- refuses chunked request bodies, and requests with more than one `Host` or
  `Content-Length`.

The download hosts gh gets redirected to, and `github.com` (for git under gh,
which inherits `HTTPS_PROXY`), are tunneled unread, without a token: the
sandbox can reach them directly anyway. Every other host is intercepted and
refused, so the proxy can't be used to reach the host's own services.

The gate is the proxy, not `gh`: anything in the sandbox can read the proxy
URL from the environment and talk to it, and gets the same treatment. The
popup can't name the requesting process, since the proxy's peer is pasta. Reads are unprompted and cover whatever
the token can read. Pushes go over ssh through ssh-agent-guard (HTTPS git
only has the placeholder).

## Forgejo: fj runs inside, the token stays outside

The same arrangement for `fj` (forgejo-cli): upstream fj, wrapped to use
forgejo-api-proxy (`internal/forgejoproxy`, sharing `internal/apiproxy` with gh-api-proxy, with a
CA, port and secret of its own) as its `HTTPS_PROXY`; the sandbox has no
Forgejo token at all. The proxy intercepts every host, tunnels none, and per
request:

- forwards only to instances there's a token for, over HTTPS, dropping the
  client's `Authorization` and adding that instance's token: the project's
  (`sandbox --fj-token HOST`, in `forgejo-tokens.json` in the volume dir, mode
  0600) if it has one, else the one from the host fj's `keys.json` - both
  re-read every request, so a new token reaches running sandboxes;
- forwards `GET`/`HEAD`, and holds everything else for a popup.

## Claude Code: a login inside, or an API key outside

By default Claude Code is logged in inside, per project, and keeps its
credentials in `~/.claude/.credentials.json` in the project's volume.
Anything running in that sandbox can read the file and use the login
elsewhere until it's revoked on claude.ai. Other projects' logins and the
host's are out of its reach. There is no way around this for a Claude
subscription: Anthropic doesn't allow a tool to store or intermediate
claude.ai credentials, so the login can't be held outside.

`guards.claudeApiKey.enable` (on the top level or per profile) keeps an API
key outside instead. The launcher
asks for the project's key on the terminal and stores it in the volume dir
(`claude-api-key`, mode 0600), out of the sandbox's reach. Claude Code inside
gets a placeholder from the managed `apiKeyHelper`, and `ANTHROPIC_UNIX_SOCKET`
plus an `http://` `ANTHROPIC_BASE_URL` make it send plain HTTP over a socket
to claude-api-proxy (`internal/claudeproxy`) on the host, which per request:

- forwards only to `api.anthropic.com`, over HTTPS, and only the paths Claude
  Code uses (messages, token counting, models, its own `/api/claude_code/`
  endpoints) - not the Files or Batches APIs the key could also reach;
- drops the client's `Authorization` and `x-api-key` and adds the real key,
  re-read every request.

There are no popups: Claude Code makes a request per turn. Anything in the
sandbox can therefore use the key through the socket while the sandbox runs,
but can't take it away. A key per project, in a Console workspace with a spend
limit, bounds what that costs.

## Opening URLs: http(s) only, behind a popup

`xdg-open` inside (also at `/usr/bin/xdg-open`) is `sandbox-bin xdg-open`
(`internal/xdgopen`). It sends the URL to open-url-guard (`internal/openurl`)
on the host, which is the gate: anything in
the sandbox can talk to the socket.

The host's `xdg-open` chooses an application from the scheme or file type, so
on sandbox-chosen input it could start any host handler. The guard only passes
it printable-ASCII `http`/`https` URLs with a host and no user info, never
through a shell, and only after a popup (default no) showing the host, the
whole URL and the requesting process. No terminal means no opening.

An approved URL still loads in the real browser with the user's logins, so it
can send a GET to a site they're signed in to or reach a browser exploit, and
the sandbox has no need of the browser to fetch ordinary pages. The popup is
what stands between sandboxed code and that session, so read the host.

## Popup answers

Every popup takes `y` (this request), `A` (always in this sandbox) or `N`, the
default, followed by Enter. No terminal, or a popup that fails, means no.

The launcher draws the popups itself (`internal/popuprelay`). It runs the
sandbox on a pty of its own and is the only process holding the real
terminal, so while a popup is up the sandbox's output is held back and every
key goes to the popup: sandboxed code can't type an answer, draw over the
popup or read what's typed. Keys typed in the first half second of a popup
are dropped, as they were meant for whatever was on screen before it - a
request timed to catch a `y` typed into the sandbox's own prompt gets
nothing. The text is drawn with anything non-printable replaced, and
wrapped rather than cut, with the line count shown when it needs scrolling.
Guards reach the launcher over a socket in its private temp dir, never bound
in.

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
dbus-daemon and ip are store paths in its generated config, and the guards
are its own binary. The guards get gh and xdg-utils from the store first on `PATH`,
the host's after - xdg-open hands approved URLs to the host's browser. The
project root is found by looking for `.git`, not by running git, which would
read a sandbox-writable repo config on the host.

## Nix daemon

Builds go through the host's nix-daemon, as the invoking user. If that user
is in the daemon's `trusted-users`, so is everything in the sandbox, and a
trusted user can have the daemon run arbitrary code as root (unsigned store
paths, its own substituters and build settings). Keep the user untrusted;
extra binary caches belong in the daemon's own configuration
(`extra-substituters`, `extra-trusted-public-keys`).

## Project config (sandbox.nix)

A project's `sandbox.nix` is in the sandbox-writable project, so it is
treated as untrusted input:

- It's evaluated by nix inside a nested sandbox of the project, never on the
  host: host evaluation could read any host file into the world-readable
  store. The host only reads the resulting manifest, a JSON file in the
  store, and checks every field (store paths, string maps, bind shapes)
  before use. sandbox.nix itself is read on the host only for the cache key,
  and never through a symlink.
- It can't change anything that runs on the host: the launcher, bwrap, pasta,
  seccomp, the guards and their settings come from the configuration
  the sandbox was started with. What it sets otherwise (command, Claude config) runs
  inside.
- What reaches beyond the inside - `binds` and `hostPorts` - needs a yes on
  the controlling terminal, again whenever it changes. The approval and the
  evaluation cache live in the project's volume dir, outside the home volume,
  where the sandbox can't write; without a terminal the sandbox doesn't
  start.

## Where the configuration comes from

The configuration the launcher runs with is built on the host, so it must
stay out of reach of every sandbox. There are two supported places:

- **Your home-manager config**, trusted like the rest of it. Don't work on
  the repo it lives in (e.g. dotfiles) in a sandbox while sandboxes run
  elsewhere: see the next section.
- **A project's flake, run from the project's remote**, following its
  default branch (`nix run github:owner/project#sandbox`) or pinned to a
  commit (`github:owner/project/<rev>`, optionally `?narHash=...`). The
  trusted input is then that branch - protected by branch protection and
  review, not the sandbox: anything merged there runs on the host of
  everyone following it - or the pinned commit, which the user reviewed.
  Without `narHash`, a pinned `github:` ref still trusts GitHub to serve
  that commit's contents; with it, nix checks them.
  Running it from a checkout (`nix run .#sandbox`) is never safe - the
  sandbox writes the checkout, `.git` included - and the launcher can't tell
  the two apart, so this rests on the user.

## Projects the host runs

A bind whose src is the project gives way to the project bind, so a repo bound
read-only for reference elsewhere (e.g. your dotfiles) is all read-write,
`.git` included, when it is the project. Like any project it is then **not a
boundary** for what the host does with it: if the repo holds anything the host
runs - shell config, a home-manager flake, this sandbox's own configuration -
sandboxed code can rewrite it (or add a git hook, `core.fsmonitor`, ...) and
get host code execution at the next switch, shell or host-side git command.
Only run trusted code in such a project. Untrusted agents and builds belong in
other projects, where those binds are read-only and per-project volumes
isolate the rest.
