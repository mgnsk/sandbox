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

## What it doesn't protect

The rest of this file says how each of these comes about; in short, a
sandbox is not a boundary for:

- **What you approve.** A yes to a popup, or to what a project's
  flake asks of the host, is yours: the sandbox only makes sure you
  were asked, and shown what for. `A` in a popup approves everything that
  guard is asked for the rest of that sandbox.
- **What's inside it.** Everything in a sandbox can read everything else
  there: a Claude Code login in the project's `$HOME`, a token pasted in,
  the project's own secrets. It has the network, so it can send them
  anywhere.
- **What the guards give without asking**: every read the GitHub and
  Forgejo tokens allow; requests on the Claude API key; commit and tag
  signatures with your signing key; the names in your `known_hosts`; with
  `git.fromHost`, your git name, email and signing key.
- **Other machines.** The LAN, a tailnet, and whatever the host can reach
  that isn't the host itself are as reachable as from the host.
- **Ports on the host's loopback.** A port bound inside shows up on the
  host's `127.0.0.1`: sandboxed code can take a port a host service isn't
  holding at the moment, and be talked to in its place.
- **Your terminal.** What a sandbox prints goes to your terminal as it is,
  escape sequences included: it can set the window's title, and with a
  terminal that allows it, your clipboard (OSC 52). Only the popups are
  drawn out of its reach.
- **The nix daemon, if it trusts you** (see "Nix daemon").
- **A project the host runs** - your dotfiles, this sandbox's own
  configuration (see "Projects the host runs").

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
  approvals and flake evaluation cache sit next to it in
  `<state dir>/<volume>/`, outside the mount, out of the sandbox's reach.
  Tokens and keys are never written there, or anywhere.

The project is bound read-write whole, so the launcher refuses to start
where that would cover host state: a project that is or contains `$HOME`,
the state dir, `/tmp`, `$TMPDIR`, `$XDG_RUNTIME_DIR` or a system directory
(`/run`, `/etc`, `/nix`, ...), or one in `$XDG_RUNTIME_DIR` or a dot
directory of `$HOME`. Over the sandbox's own `/tmp` or runtime dir, the
host's would bring its sockets in: tmux, the session bus, an ssh agent. A
`.git` only makes its directory the project when that directory is the
user's own - not one another user left in `/tmp`.

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
project flake), and then only at `127.0.0.1:<port>` inside:

- pasta's `-T`/`-U` mirror just those host loopback ports, instead of its
  default of every listener the host has;
- `--map-host-loopback none` and `--map-guest-addr none` remove the addresses
  pasta would otherwise translate to the host;
- the host's global addresses (LAN, tailscale, docker bridges, ...) get
  `prohibit` routes in the namespace before bwrap drops capabilities.

The address list is a snapshot: an address the host gains after the sandbox
started stays reachable until the next start. A cloud host's metadata
service (`169.254.169.254`), which hands out the instance's credentials, is
prohibited the same way. Other machines on the LAN or tailnet are not
restricted.

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
port. The secret is on no command line, which other users of the host could
read: bwrap takes its arguments from a file only the user can read.

For the two API hosts (`ghproxy.TokenHosts`), it answers the TLS handshake
itself, with a certificate from a CA it generated at startup. The CA's key
exists only in the proxy's memory and dies with it, and its name constraints
limit what it can sign for to those hosts. Its certificate is trusted
sandbox-wide (`SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and
`REQUESTS_CA_BUNDLE` all name `SANDBOX_CA_FILE`, the system bundle plus the guards' CAs, which is
also bound over the system bundle at `/etc/ssl/certs/ca-bundle.crt`), so any
client completes TLS with the guard. That trust can't be used to read other
traffic: nothing inside can mint a certificate, and only connections the
router sends to a guard ever meet one. Inside the tunnel, per request, it:

- requires `Host` to be the `CONNECT` target;
- drops the client's `Authorization` and adds the real token;
- forwards REST `GET`/`HEAD`, and GraphQL documents containing only queries
  when they come as the endpoint is known to take them: a `POST` of JSON,
  with no query in the URL;
- holds everything else - REST writes, GraphQL mutations and subscriptions,
  anything it can't parse - for a popup (see "Popup answers"). The popup
  shows what would be written: a JSON body of up to 256 kB (its first 32 kB;
  any other body is said to be there, with its size and type), and for
  GraphQL the operations, the document and the variables;
- refuses protocol upgrades (`Upgrade`), and drops the headers that have a
  server treat a request as another method (`X-HTTP-Method-Override`, ...).

Requests are read and written again by Go's HTTP server and client, never
passed on as bytes, so a request can't be smuggled in another's body; one
with more than one `Host`, or conflicting `Content-Length`s, is refused.

The router sends only the two API hosts here; `github.com`, the download
hosts and everything else it dials itself. The proxy still tunnels the
download hosts and `github.com` unread, without a token, for a client that
talks to it directly, and refuses every other host, so it can't be used to
reach the host's own services.

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

`NO_PROXY` keeps loopback direct, for dev servers; a host `HTTPS_PROXY`
passed in with `passEnv` is replaced, and the router dials out directly.
Clients that ignore `HTTPS_PROXY` bypass it, and reach the APIs without a
token.

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
- forwards `GET`/`HEAD`, and holds everything else for a popup, which
  shows a JSON body as the GitHub guard's does.

Its CA is constrained to the instances there's a token for.

## Token commands

Never run `gh auth login` or `fj auth login` inside the sandbox: a token
stored inside is readable by all sandboxed code and bypasses the proxies
and their popups. Nothing inside can be made to refuse a token pasted into
it, so the sandbox makes the usual ways fail and reports the rest:

- with the GitHub guard on, `GH_TOKEN` is set, and gh refuses `auth login`
  while it is (clearing it gets past that);
- forgejo-api-proxy refuses the OAuth token exchange of `fj auth login`, for
  instances with a token command;
- in the Claude Code of `sandbox.lib.mkClaude`, a hook
  (`nix/claude/deny-cli-login.sh`) denies `gh auth login|refresh|token` and
  `fj auth login|add-token|add-key`, guard or not. It's in the project's
  flake, which sandboxed code can edit: a check against a slip, no more;
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
- **The project's flake** (or `.sandbox.yml`, below): sandboxed code can edit it, so its
  commands are shown on the terminal and run only after a yes, stored with
  the project's other approvals and asked again when one changes; without a
  terminal the sandbox doesn't start. A command the user's config overrides,
  or for a guard that's off, is neither shown nor run. The approval is the only check: a user who approves a command that
  does more than print a token has run it.

## Claude Code: a login inside, or an API key outside

By default Claude Code is logged in inside, per project, and keeps its
credentials in its config dir in the project's volume
(`~/.claude-project/.credentials.json` for `sandbox.lib.mkClaude`'s,
`~/.claude/` for another).
Anything running in that sandbox can read the file and use the login
elsewhere until it's revoked on claude.ai. Other projects' logins and the
host's are out of its reach. There is no way around this for a Claude
subscription: Anthropic doesn't allow a tool to store or intermediate
claude.ai credentials, so the login can't be held outside.

A Claude API key command (`guards.claudeApiKey.tokenCommand`, see "Token
commands") keeps an API key outside instead: printed on the host at each
start and held in claude-api-proxy's memory, never on disk. Claude Code inside
gets a placeholder from an `apiKeyHelper` (`sandbox.lib.mkClaude` sets it
when the guard runs), and `ANTHROPIC_UNIX_SOCKET`
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

Claude Code's configuration - settings, hooks, MCP servers, memory - is the
project's (`sandbox.lib.mkClaude` in its flake) or the user's own profile's
(`~/.claude`, linked into the volume from home-manager). Either is inside
the sandbox's reach: the project's in the project, the links in the home
volume, which the sandbox can replace until the next start. The sandbox puts
none of its own in place that sandboxed code couldn't change; what it says
about itself is `/etc/sandbox/AGENTS.md`, read-only, and its guards don't
depend on any of it.

## Opening URLs: http(s) only, behind a popup

`xdg-open` inside (also at `/usr/bin/xdg-open`) is `sandbox-bin xdg-open`
(`internal/xdgopen`). It sends the URL to open-url-guard (`internal/openurl`)
on the host, which is the gate: anything in
the sandbox can talk to the socket.

The host's `xdg-open` chooses an application from the scheme or file type, so
on sandbox-chosen input it could start any host handler. The guard only passes
it printable-ASCII `http`/`https` URLs with a host and no user info, never
through a shell, and only after a popup (default no) showing the host, the
whole URL and what the requesting process says of itself (its command line
and directory are its own words). A host with a percent-escape is refused:
decoded, it could show as a name it isn't. No terminal means no opening.

An approved URL still loads in the real browser with the user's logins, so it
can send a GET to a site they're signed in to or reach a browser exploit, and
the sandbox has no need of the browser to fetch ordinary pages. The popup is
what stands between sandboxed code and that session, so read the host.

## SSH agent: every signature asks, but git's with its key

Inside, `SSH_AUTH_SOCK` is ssh-agent-guard's socket (`internal/sshagent`),
never the agent's own. The guard passes on listing the keys and, after a
popup, signing; adding, removing and locking keys and every extension but
`session-bind` are refused, unforwarded.

- **A signature is whatever its key is trusted for.** The guard sees the
  data to sign, not who will check it. The popup says which kind it is - a
  login and its user name, an `ssh-keygen -Y sign` signature and its
  namespace, or neither - and the key's fingerprint.
- **A login names its server when ssh binds its session.** OpenSSH's ssh
  (8.9 and later) sends the agent `session-bind@openssh.com` before a
  login: the server's host key and its signature over the session's
  identifier, which the login's data begins with. The guard checks that
  signature and names the server by that host key from your `known_hosts`
  on the host - never the sandbox's, which sandboxed code can write - so an
  approved login only works with the holder of that key. A hashed entry
  names the host the client's command line claims, only when that entry
  holds the key; a revoked key says so. A login whose session no verified
  bind on its connection names - from other clients, or a bind refused -
  may be to any host that takes the key, and the popup says so. The guard
  keeps binds to itself, so the agent never sees them.
- **"Always" for a named server covers that server alone**: later logins to
  the same host key by the same route (directly, or through an agent
  forwarded to the same host). "Always" for anything else - an unbound
  login or other data - covers all of that, but no named server's logins.
- **Commit and tag signatures don't ask**, with the key git inside signs
  with: `git.signingKey` (or its command's output), and the `user.signingKey`
  of your global git config on the host, which the launcher reads at start
  (`git config --global`, run from `/`). Sandboxed code can therefore sign
  any commit or tag as you with that key, and push it where it can push.
  With any other key in the agent - one meant for logging in somewhere - a
  git signature asks like the rest.
- **The agent's own restrictions on where a key may be used**
  (`ssh-add -h`) don't hold through the guard: it doesn't pass on the
  `session-bind` extension they rest on, so the agent sees local use.

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
project's flake once approved (see "Project config").

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

- Leaving a global out of the registry's listing isn't enough: its numeric
  name is a small integer, and a client that guesses it can send a
  `wl_registry.bind` for it all the same. wl-veil 0.1.5, the last release,
  forwards such a bind. The sandbox builds wl-veil from the upstream commit
  that refuses it (`nix/packages.nix`, mahkoh/wl-proxy#144): a bind of a
  global the client wasn't told of, or of a higher version than it was
  told, is answered with a protocol error, which ends the client's
  connection. The allowlist rests on that.
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
- A project's flake may add to the allowlist and remove from it; the
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
nothing. Nor is what the terminal itself sends in answer to a query the
sandbox made before the popup (its title, its colors) taken for keys. The text is drawn with anything non-printable replaced, and
wrapped rather than cut, with the line count shown when it needs scrolling.
Guards reach the launcher over a socket in a private directory of its own in
`$XDG_RUNTIME_DIR`, which is never bound in and which no project can be in.

### What `A` covers

`A` lasts as long as the guard that was asked: it is only held in that
guard's memory, and each `sandbox` run starts its own guards and kills them
on exit. The next sandbox asks again, and so does another one running
on the same project. It covers one guard only, so `A` on a gh popup doesn't
cover ssh or URLs, and it covers everything in the sandbox, not the process
that asked.

So `A` takes the user out of the loop for anything sandboxed code does next:

- **ssh**: any authentication with any key the agent holds, to any host - the
  guard sees neither the destination nor what the session is for, so this isn't
  limited to `git push`.
- **gh** / **fj**: any write the token allows, in any repo it reaches.
- **URLs**: any URL `openurl.Validate` passes, loaded unseen in the logged-in
  browser - the risk described above, with no host left to read.

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

## Host userland: none

Nothing of the host's `/usr`, `/bin` or `/lib` is bound in. Every program
inside comes from the nix store: a fixed minimal set on `PATH` (bash, nix,
git with its pager and editor, ssh, terminfo, stdenv's basics and a few
tools every session reaches for: jq, curl, rg, which, ps, zip - no
configuration adds to it; other tools come from the project's dev shell or
the user's profile),
`/bin/sh`, `/bin/env`, `/usr/bin/env` and `/usr/bin/xdg-open` from a small
store directory, a managed read-only `/etc/bashrc` and `/etc/profile` (loading
bash-completion) from the store, and nix-ld at the dynamic loader's path for prebuilt
binaries. From the host's `/etc` only identity and name resolution are bound
(`passwd`, `group`, `hosts`, `resolv.conf`, `nsswitch.conf`, `localtime`);
CA certificates come from the store too. With the ssh agent guard, the
user's `~/.ssh/known_hosts` is bound read-only as the system-wide one: every
project sees which hosts the user connects to, unless the file is hashed.

All of it is mounted on a tmpfs root, which is made read-only once the
mounts are in place. Left writable, it would let sandboxed code move `/etc`
aside and make its own - its own `AGENTS.md`, startup files and `hosts` -
for the rest of that sandbox. What can be written inside is
`/tmp`, `/dev/shm`, `$XDG_RUNTIME_DIR`, the home volume, the project and
read-write binds.

What the launcher runs is from the store too: bwrap, pasta, dbus-daemon and
ip are store paths in its generated config, and the guards are its own
binary. From the host's `PATH` it runs only what is the user's own: their
token commands, and their `git`, for `git config --global` (the identity
`git.fromHost` asks for, and the signing key the ssh agent guard doesn't
ask about) - from `/`, never in a project. The guards get xdg-utils from
the store first on `PATH`, the host's after - xdg-open hands approved URLs
to the host's browser. The project root is found by looking for `.git`, not
by running git, which would read a sandbox-writable repo config on the
host.

## Nix daemon

Builds go through the host's nix-daemon, as the invoking user. If that user
is in the daemon's `trusted-users`, so is everything in the sandbox, and a
trusted user can have the daemon run arbitrary code as root (unsigned store
paths, its own substituters and build settings). Keep the user untrusted;
extra binary caches belong in the daemon's own configuration
(`extra-substituters`, `extra-trusted-public-keys`).

## Project config (the flake)

A project's `flake.nix` is in the sandbox-writable project, so its sandbox
configuration (the default dev shell's `sandbox`, which
`sandbox.lib.mkShell` sets) is treated as untrusted input:

- It's evaluated by nix inside a nested sandbox of the project, never on the
  host: host evaluation could read any host file into the world-readable
  store. That sandbox gets no guards, tokens or host ports. The host only
  reads the resulting manifest, a JSON file in the store, and checks every
  field (string maps, bind shapes) before use. `flake.nix` and `flake.lock`
  themselves are read on the host only for the cache key, and never through
  a symlink.
- The configuration is a module, evaluated with the options of the sandbox
  that runs it, not of the version the flake pins: the project picks
  values, never what they mean.
- The manifest is whatever the code in that sandbox printed, and a store
  path can be a link to anywhere. So the manifest is read only as a regular
  file that is a store path itself; nothing in it names a path the host
  would resolve.
- It can't change anything that runs on the host: the launcher, bwrap, pasta,
  seccomp, the guards and their settings come from the configuration
  the sandbox was started with. What it sets otherwise (the command) runs
  inside.
- What reaches beyond the inside - `binds`, `hostPorts`, token commands,
  which run on the host, and the Wayland guard (turning it on, or adding a
  global to its allowlist) - needs a yes on the controlling terminal. The
  approvals and the evaluation cache live in the project's volume dir,
  outside the home volume, where the sandbox can't write; without a terminal
  the sandbox doesn't start.
- Each thing is approved on its own: a port, a command, the display, a
  global. A start asks when it would use one that isn't approved, showing
  all it would use, so one that uses less - the user's config has that
  token command, or a project drops a port - doesn't ask. The binds are
  approved as one list: one may cover part of another (read-only, inside a
  read-write one), so a shorter list is asked about too. An approval of
  something the project no longer asks for is dropped at the next start:
  bringing it back asks again.
- What's approved is what's shown. A command, bind or port with a control
  character - an escape sequence or carriage return that would show
  something else than what then runs - is refused, and what was typed
  before the question doesn't answer it. A bind is approved for where it
  leads: its source must be an absolute path outside the project and the
  state dir, which the sandbox writes, and one that resolves elsewhere than
  it did when approved is asked about again.

## Per-user project settings (.sandbox.yml)

`.sandbox.yml` is in the project too, so it's untrusted like the flake:
read on the host without following a symlink, decoded strictly (an unknown
field is an error). Its token commands and signing key command go through
the same approval as the flake's (whose own signing key command is
approved too); a signing key command's output must be an ssh public key.
Its git identity and signing key only set git's environment inside. Being
gitignored keeps it out of commits, not out of the sandbox's reach - and the
sandbox can read it, which is fine: it holds commands and public data, not
secrets.

`git.fromHost` (in either file) runs only `git config --global --list` on the
host, once, from `/` - never in the project, whose `.git` the sandbox can
write - uses a fixed set of its keys, and reads a signing key's `.pub`
file without following a link at its last component. The values only set
git's environment inside. All host commands (token and signing key commands) run
from `/` too, as the guards and what they start do (the host's `xdg-open`,
the browser), so nothing the sandbox wrote in the project reaches them.

## Profiles

A profile of the user's config applies by where the sandbox starts
(`paths`), never by a file in the project, which the sandbox writes and
could otherwise use to pick a profile with more of the host.

## Where the configuration comes from

The configuration the launcher runs with is built on the host, so it must
stay out of reach of every sandbox. There are two supported places:

- **This repo's default package, run from its remote** (`nix run
  github:mgnsk/sandbox`, optionally pinned to `/<rev>` and `?narHash=...`):
  the default settings, reading no user config. The trusted input is this
  repo's default branch, or the commit pinned. A local clone of it is a
  checkout like any other: don't run the sandbox from one you work on in a
  sandbox. Without `narHash`, a pinned `github:` ref still trusts GitHub to
  serve that commit's contents; with it, nix checks them.
- **Your home-manager config**, trusted like the rest of it. Don't work on
  the repo it lives in (e.g. dotfiles) in a sandbox while sandboxes run
  elsewhere: see the next section.

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

The same goes for a sandboxed project's own flake: `nix develop` (or `nix
run`, direnv's `use flake`) on the host runs what the sandbox may have put
there, outside it. `sandbox.lib.mkShell`'s shell hook re-runs `nix develop`
in the sandbox, but that hook is in the flake too, run on the host by the
very `nix develop` it redirects: it saves typing `sandbox`, not a tampered
flake. After a session that could have edited the flake, enter with
`sandbox`, which evaluates the flake only inside.
