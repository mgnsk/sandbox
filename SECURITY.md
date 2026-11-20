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
  host has there is not visible inside. The project's
  `sandbox.nix` approvals and evaluation cache sit next to it in
  `<state dir>/<volume>/`, outside the mount, out of the sandbox's reach.
  Tokens and keys are never written there, or anywhere.

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
when `sandbox` starts, or in `hostPorts` (the user's config, or an approved
`sandbox.nix`), and then only at `127.0.0.1:<port>` inside:

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

Inside, `GH_TOKEN` is a fixed placeholder, and every process's
`HTTPS_PROXY` is the router (`internal/router`, see "The router" below),
which chains `CONNECT`s for the GitHub API hosts to gh-api-proxy
(`internal/ghproxy`). Any `gh` works, wherever it comes from; the sandbox
ships none. The proxy runs on the host and holds the real token, in memory
only: the one a token command printed at start (see "Token commands" below),
piped to the proxy by the launcher - never on disk, in argv or in an
environment. Nothing on the host runs gh or reads its login (unless the
user's token command is `gh auth token`), so a sandbox without a token
command gets no GitHub access at all. It listens on a free port of the host's
loopback, which pasta's `-T` maps into the sandbox, and only takes a `CONNECT`
carrying a random per-launch secret (`SANDBOX_GH_PROXY`, handed to the
router and left out of the command's environment, sent as Basic
`Proxy-Authorization`), since anything on the host's loopback can reach the
port.

For the two API hosts (`TOKEN_HOSTS`), it answers the TLS handshake itself,
with a certificate from a CA it generated at startup. The CA's key exists only
in the proxy's memory and dies with it. Its certificate is trusted
sandbox-wide (`SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and
`REQUESTS_CA_BUNDLE` all name `SANDBOX_CA_FILE`, the system bundle plus the guards' CAs, which is
also bound over the system bundle at `/etc/ssl/certs/ca-bundle.crt`), so any
client completes TLS with the guard. That trust can't be used to read other
traffic: nothing inside can mint a certificate, and only connections the
router sends to a guard ever meet one. Inside the tunnel, per request, it:

- requires `Host` to be the `CONNECT` target;
- drops the client's `Authorization` and adds the real token;
- forwards REST `GET`/`HEAD` and GraphQL documents containing only queries;
- holds everything else - REST writes, GraphQL mutations and subscriptions,
  anything it can't parse - for a popup (see "Popup answers");
- refuses chunked request bodies, and requests with more than one `Host` or
  `Content-Length`.

The router sends only the two API hosts here; `github.com`, the download
hosts and everything else it dials itself. The proxy still tunnels the
download hosts and `github.com` unread, without a token, for a client that
talks to it directly, and intercepts and refuses every other host, so it
can't be used to reach the host's own services.

The gate is the proxy, not `gh`: anything in the sandbox that honors
`HTTPS_PROXY` - curl, a script, an npm package - reaches it through the
router and gets the same treatment, as does anything that finds the guard's
URL (the router's environment is readable inside). The
popup can't name the requesting process, since the proxy's peer is pasta. Reads are unprompted and cover whatever
the token can read. Pushes go over ssh through ssh-agent-guard (HTTPS git
only has the placeholder).

## The router

With a GitHub or Forgejo token command set, `sandbox-bin init` starts the router
inside, before the command, in a session of its own (so a Ctrl-C to the
command doesn't stop it). It listens on the sandbox's loopback, and every
process gets it as `HTTPS_PROXY`, with a random per-start secret in the URL:
ports bound inside are forwarded to the host's loopback, so without it any
host process could use the guards' tokens through the router.

It only answers `CONNECT`, and opens the tunnel one of three ways: chained
to gh-api-proxy (the GitHub API hosts), chained to forgejo-api-proxy (hosts
that guard takes), or dialed by itself, from inside, over the sandbox's own
network. The guards still see only their own hosts, so routing every client
through it adds no way out to the host: what it dials, the client could have
dialed itself.

It runs as the sandbox's user, so code inside can kill or replace it; that
breaks the GitHub and Forgejo APIs for proxy-aware clients until the next
start, and gains nothing a client couldn't already do with the guards' URLs.

## Forgejo: fj runs inside, the token stays outside

The same arrangement for Forgejo, with forgejo-api-proxy
(`internal/forgejoproxy`, sharing `internal/apiproxy` with gh-api-proxy, with a
CA, port and secret of its own); the sandbox has no Forgejo token at all. The
router doesn't know the instances: it offers every `CONNECT` the GitHub
proxy didn't take to this one first. The proxy answers 404 at once, unread,
for a host it has no token for (the router then dials it itself), and
intercepts the rest; it tunnels none, and per request:

- forwards only to instances there's a token for, over HTTPS, dropping the
  client's `Authorization` and adding that token - printed by that host's
  token command at start and held in memory, as for GitHub. The host fj's
  `keys.json` is never read;
- refuses Forgejo's OAuth endpoints (`/login/oauth/...`, path cleaned and
  lowercased first), where `fj auth login` would trade its code for a token
  stored inside;
- forwards `GET`/`HEAD`, and holds everything else for a popup.

## Token commands

Never run `gh auth login` or `fj auth login` inside the sandbox: a token
stored inside is readable by all sandboxed code and bypasses the proxies
and their popups. Nothing inside can be made to refuse a token pasted into
it, so the sandbox makes the usual ways fail and reports the rest:

- with the GitHub guard on, `GH_TOKEN` is set, and gh refuses `auth login`
  while it is (clearing it gets past that);
- forgejo-api-proxy refuses the OAuth token exchange of `fj auth login`, for
  instances with a token command;
- a Claude Code hook (`nix/claude/deny-cli-login.sh`) denies `gh auth
  login|refresh|token` and `fj auth login|add-token|add-key`, guard or not;
- at each start, init warns of a login stored in the volume - hosts in gh's
  `hosts.yml` or fj's `keys.json` - and secret-service-guard of gh tokens
  among the project's items in the host keyring (when it's unlocked), with
  the commands to remove them.

The GitHub and Forgejo tokens, and the Claude API key, come from shell
commands the launcher runs on the host at each start, with bash from the store, the user's environment
(their `PATH`, so a secret manager's CLI is their own) and terminal (so it
can prompt). Each command's output must be a valid token; the launcher hands
it to its guard over a pipe, and nothing else keeps it.

A command is code run on the host as the user, outside the sandbox, so where
it comes from is the boundary:

- **The user's config** (home-manager, a profile in it):
  trusted like the rest of it, run without asking. It wins over the
  project's for the same guard or host.
- **The project's `sandbox.nix`** (or `.sandbox.yml`, below): sandboxed code can edit it, so its
  commands are shown on the terminal and run only after a yes, stored with
  the project's other approvals and asked again whenever any of them
  changes; without a terminal the sandbox doesn't start. A command the
  user's config overrides, or for a guard that's off, is neither shown nor
  run. The approval is the only check: a user who approves a command that
  does more than print a token has run it.

## Claude Code: a login inside, or an API key outside

By default Claude Code is logged in inside, per project, and keeps its
credentials in `~/.claude/.credentials.json` in the project's volume.
Anything running in that sandbox can read the file and use the login
elsewhere until it's revoked on claude.ai. Other projects' logins and the
host's are out of its reach. There is no way around this for a Claude
subscription: Anthropic doesn't allow a tool to store or intermediate
claude.ai credentials, so the login can't be held outside.

A Claude API key command (`guards.claudeApiKey.tokenCommand`, see "Token
commands") keeps an API key outside instead: printed on the host at each
start and held in claude-api-proxy's memory, never on disk. Claude Code inside
gets a placeholder from the managed `apiKeyHelper`, and `ANTHROPIC_UNIX_SOCKET`
plus an `http://` `ANTHROPIC_BASE_URL` make it send plain HTTP over a socket
to claude-api-proxy (`internal/claudeproxy`) on the host, which per request:

- forwards only to `api.anthropic.com`, over HTTPS, and only the paths Claude
  Code uses (messages, token counting, models, its own `/api/claude_code/`
  endpoints) - not the Files or Batches APIs the key could also reach;
- drops the client's `Authorization` and `x-api-key` and adds the real key.

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

## Secret Service: the host's keyring, one project's items

Inside there is only a private D-Bus bus, with secret-service-guard's
Secret Service on it; the host's session bus is never bound in. The guard,
outside, keeps the items in the host's own Secret Service (its default
collection), so they are as safe at rest as the host's other credentials.
`guards.secretService.enable` requires one: without one running or
activatable on the host's session bus, the sandbox doesn't start, rather
than keep credentials anywhere else.

- **Each project sees only its own items.** The guard marks every item it
  creates with `sandbox-project` = the project's path, and adds that to
  every search; inside there is no other way to name a host item. Item
  objects inside are the guard's own numbers, for host items it found that
  way.
- **The host's programs never find a sandbox's item.** The sandbox's
  attribute names are stored prefixed (`service` as `sandbox:service`), so
  a planted item can't answer a host program's lookup - gh's own token
  item, say - and hand it a credential of the sandbox's choosing. Labels
  read `sandbox <project>: <label>`.
- **Unlocking is the host's.** A locked keyring is unlocked when the
  sandbox first needs it, through the host's own prompt; the guard has no
  password, and a dismissed prompt fails the request. Inside, `Unlock`
  always "succeeds" and nothing ever sees a prompt object.
- **The secrets cross the host's bus unencrypted** (a "plain" session, one
  per transfer): it is the user's own bus, which the sandbox can't reach.

## Wayland: a proxy with an allowlist, never the socket

Off unless `guards.wayland.enable` is set: by the user's own config, or by a
project's sandbox.nix once approved (see "Project config").

A Wayland compositor gives a client whatever it offers any client. On
wlroots compositors that includes the screen's contents
(`zwlr_screencopy_manager_v1`, `ext_image_copy_capture_manager_v1`), the
clipboard at any time (`zwlr_data_control_manager_v1`,
`ext_data_control_manager_v1`), synthetic input
(`zwp_virtual_keyboard_manager_v1`, `zwlr_virtual_pointer_manager_v1`),
surfaces over everything (`zwlr_layer_shell_v1`) and other clients' windows.
So the compositor's socket is never bound in. Clients inside get the socket
of a proxy on the host, wl-veil, started with an allowlist of globals
(interface names): what isn't on it is neither announced to a client nor
bound for it.

- wl-veil as released only leaves the other globals out of the registry's
  listing, and forwards a `wl_registry.bind` of any name a client sends: a
  client that guesses a hidden global's numeric name (they're small
  integers) binds it all the same. The sandbox builds wl-veil with a patch
  (`nix/patches/wl-veil-bind.patch`) that has it renumber the globals it
  announces and forward binds of those only. The allowlist rests on that
  patch.
- The default allowlist (`nix/wayland.nix`) has what a program needs for
  its own windows. It leaves out the clipboard and drag-and-drop
  (`wl_data_device_manager`, `zwp_primary_selection_device_manager_v1`):
  with them, a window inside reads the host's selection whenever it has the
  keyboard focus, and sets it. Asking for the focus (`xdg_activation_v1`),
  keeping the screen from locking and reading the outputs' layout or the
  user's idle time are left out too.
- What stays: a client inside draws what it likes in its own windows,
  titled as it likes - a convincing prompt included - and gets the keyboard
  and pointer input its windows are given. Nothing marks its windows as the
  sandbox's.
- The proxy runs on the host and parses every message the sandbox sends: a
  bug in it is a way out. It's a young program in Rust, with one maintainer.
  It gets no popup socket, no token and nothing but the compositor's socket.
- It listens in a temp dir of its own, which only the launcher knows, and
  goes with the sandbox.
- A project's sandbox.nix may add to the allowlist and remove from it; the
  user's own changes are applied last. Turning the guard on and adding a
  global need the user's yes; names are checked (`[a-z][a-z0-9_]*`) before
  they reach wl-veil's command line.

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

### As desktop notifications too

In a sandbox with a Wayland display (and `guards.notifications.enable`, on by
default), the launcher also shows a request as a desktop notification
(`internal/notify`), unless it is for a process on the sandbox's own
terminal. The terminal popup is always there as well; the first answer
counts.

- **Where a request comes from** is the session of the process the guard
  serves, read from the host's `/proc` when it connects (as its command line
  is, see `internal/peer`) and compared with the session whose controlling
  terminal is the sandbox's pty. Only a match is "from the terminal". A
  process inside can leave that session (`setsid`) and so get a notification
  shown for its request; it can't make a request look as if it came from the
  terminal without being on it, and either way the request still needs an
  answer.
- **The sandbox can't answer or forge one.** The launcher sends it on the
  host's session bus; inside there is only the private bus with the Secret
  Service. Through the Wayland guard a client inside has no synthetic input
  and no surfaces over other windows, so it can't click the notification
  either - but it can open a window of its own to draw the eye, or time a
  request for when a click is about to land. Answers in the first half second
  after a notification is shown are dropped, as keys are, and it is shown
  again.
- **Not always all that's approved.** On the terminal a request is shown
  whole, and approved for exactly that. Notification daemons cut or collapse
  long bodies, each its own way, and nothing tells the sender, so the
  launcher cuts text beyond 400 characters or 10 lines itself and ends it
  with a line saying so. The answers stay: one given there approves the
  whole request on the strength of its start. The guards put what decides
  it first - a URL's host before the URL, an API request's method and path
  before its body - but what follows the cut is unseen unless the user looks
  at the terminal, and sandboxed code chooses what's there (a URL's query, a
  request's body). Text is shown with anything non-printable replaced, and
  escaped where the daemon reads markup.
- **Not a boundary of its own.** Anything on the host's session bus can
  send, close or answer notifications; that is the host, which is trusted
  here. A notification that expires or is hidden (do-not-disturb) changes
  nothing: the request waits on the terminal. Closing one without an answer
  is a no.
- The launcher connects to the bus named by `DBUS_SESSION_BUS_ADDRESS`, or
  the one at `$XDG_RUNTIME_DIR/bus`, and never starts one.

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
inside comes from the nix store: a fixed minimal set on `PATH` (bash, nix,
git, ssh, terminfo and stdenv's basics - no configuration adds to it; other tools come
from the project's dev shell or the user's profile),
`/bin/sh`, `/bin/env`, `/usr/bin/env` and `/usr/bin/xdg-open` from a small
store directory, a managed read-only `/etc/bashrc` and `/etc/profile` (loading
bash-completion) from the store, and nix-ld at the dynamic loader's path for prebuilt
binaries. From the host's `/etc` only identity and name resolution are bound
(`passwd`, `group`, `hosts`, `resolv.conf`, `nsswitch.conf`, `localtime`);
CA certificates come from the store too.

The launcher itself runs nothing from the host's `PATH` either: bwrap, pasta,
dbus-daemon and ip are store paths in its generated config, and the guards
are its own binary. The guards get xdg-utils from the store first on `PATH`,
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
- What reaches beyond the inside - `binds`, `hostPorts`, token commands,
  which run on the host, and the Wayland guard (turning it on, or adding a
  global to its allowlist) - needs a yes on the controlling terminal, again
  whenever it changes. The approval and the
  evaluation cache live in the project's volume dir, outside the home volume,
  where the sandbox can't write; without a terminal the sandbox doesn't
  start.

## Per-user project settings (.sandbox.yml)

`.sandbox.yml` is in the project too, so it's untrusted like `sandbox.nix`:
read on the host without following a symlink, decoded strictly (an unknown
field is an error). Its token commands and signing key command go through
the same approval as `sandbox.nix`'s (whose own signing key command is
approved too); a signing key command's output must be an ssh public key.
Its git identity and signing key only set git's environment inside. Being
gitignored keeps it out of commits, not out of the sandbox's reach - and the
sandbox can read it, which is fine: it holds commands and public data, not
secrets.

`git.fromHost` (in either file) runs only `git config --global --get` on the
host, for a fixed set of keys, from `/` - never in the project, whose `.git`
the sandbox can write - and reads a signing key's `.pub` file without
following a link at its last component. The values only set git's
environment inside. All host commands (token and signing key commands) run
from `/` too, so nothing the sandbox wrote in the project reaches them.

## Where the configuration comes from

The configuration the launcher runs with is built on the host, so it must
stay out of reach of every sandbox. There are three supported places:

- **This repo's default package, run from its remote** (`nix run
  github:mgnsk/sandbox`, optionally pinned to `/<rev>` and `?narHash=...`):
  the default settings, reading no user config. The trusted input is this
  repo's default branch, or the commit pinned. A local clone of it is a
  checkout like any other: don't run the sandbox from one you work on in a
  sandbox.

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
