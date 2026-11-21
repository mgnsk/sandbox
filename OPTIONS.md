# Options

Every option, with its type and default. Generated from the option
declarations in `nix/` by `make options`: change those, not this file.
The [README](README.md#configuring-the-sandbox) says what they're for
and where a setting belongs.

- [In your config, a profile or a project](#in-your-config-a-profile-or-a-project)
- [Your sandbox config](#your-sandbox-config)
- [A project's sandbox](#a-projects-sandbox)
- [A project's Claude Code](#a-projects-claude-code)

## In your config, a profile or a project

These are the same in all three. A profile's go over your config's for
its projects, and a project's over both - where its binds take your yes
on the terminal first.

### `binds`

Host paths bound in, after the per-project home volume (so they shadow it).

- Type: `list of (submodule)`
- Default: `[ ]`

### `binds.*.dst`

Path inside; the same as src when null.

- Type: `null or string`
- Default: `null`

### `binds.*.hideGit`

Put an empty tmpfs over src/.git, so a repo bound for reference doesn't show its history. A bind of the project itself is skipped in favour of the project bind, read-write with .git.

- Type: `boolean`
- Default: `false`

### `binds.*.mode`

Read-only, or read-write.

- Type: `one of "ro", "rw"`
- Default: `"ro"`

### `binds.*.optional`

Skip silently when src doesn't exist.

- Type: `boolean`
- Default: `false`

### `binds.*.src`

Host path. `~` and `$HOME`, `$USER`, `$XDG_RUNTIME_DIR` are expanded at start.

- Type: `string`

## Your sandbox config

`programs.sandbox.settings` in home-manager. Trusted like the rest of
your config: nothing here is asked about. A profile
(`profiles.<name>`) also takes the options above and the guards' token
commands, for its projects.

### `guards.claudeApiKey.tokenCommand`

A shell command that prints a Claude API key, run like
guards.github.tokenCommand. With one, Claude Code inside sends its
requests to a host proxy that adds the key - in place of logging in
inside, so not for Claude subscriptions. sandbox.lib.mkClaude's
Claude Code takes the placeholder key it needs then; another needs
`apiKeyHelper` set to `echo sandbox-placeholder`. Trusted, as your config: run without asking, and it wins over a project's, which runs only once you approve it. A profile can set its own.

- Type: `null or string`
- Default: `null`
- Example: `"op read op://Employee/Claude/credential"`

### `guards.forgejo.tokenCommands`

The same per Forgejo instance, by host[:port]: each command prints
that instance's token. Trusted, as your config: run without asking, and it wins over a project's, which runs only once you approve it. A profile can set its own.

- Type: `attribute set of string`
- Default: `{ }`

Example:

```nix
{
  "codeberg.org" = "op read op://Employee/Codeberg/token";
}
```

### `guards.github.tokenCommand`

A shell command that prints the GitHub token, e.g. from a secret
manager, run on the host at each start. With one, GitHub API
requests from inside - any gh's, or any other client's - go through
a host proxy that adds the token and holds writes for a popup. The
token is handed to the proxy in memory: never on disk, never inside
the sandbox. Without one that proxy doesn't run, and requests go
out without a token. Trusted, as your config: run without asking, and it wins over a project's, which runs only once you approve it. A profile can set its own.

- Type: `null or string`
- Default: `null`
- Example: `"op read op://Employee/GitHub/token"`

### `guards.notifications.enable`

In a sandbox with a Wayland display (guards.wayland), show a
guard's popup as a desktop notification as well, with the same
answers, when the request doesn't come from the terminal the
sandbox runs on - from a window inside, say. The popup on the
terminal stays, and the first answer counts. Needs a notification
daemon that shows actions on your session bus.

- Type: `boolean`
- Default: `true`

### `guards.openUrl.enable`

xdg-open inside opens http(s) URLs in the host's browser, after a popup.

- Type: `boolean`
- Default: `true`

### `guards.secretService.enable`

A private D-Bus bus with a Secret Service for libsecret users (gh, ...),
keeping each project's items apart in the host's own Secret Service
(gnome-keyring, KeePassXC, ...). With it on, a sandbox doesn't start
without one on the host's session bus.

- Type: `boolean`
- Default: `true`

### `guards.sshAgent.enable`

Proxy the host's ssh agent, with non-commit-signing requests behind a popup.

- Type: `boolean`
- Default: `true`

### `guards.sshAgent.path`

Where the proxied socket appears inside; SSH_AUTH_SOCK points there.

- Type: `string`
- Default: `"$XDG_RUNTIME_DIR/ssh-agent.sock"`

### `guards.sshAgent.socket`

Host agent socket; $SSH_AUTH_SOCK at start when null.

- Type: `null or string`
- Default: `null`

### `guards.wayland.enable`

Windows on the host's Wayland display, for GUI programs inside:
through a proxy (wl-veil) that passes on only an allowlist of
the compositor's globals, as $XDG_RUNTIME_DIR/wayland-0 inside.
The real socket is never bound in. null leaves it to each
project's sandbox module, whose guards.wayland.enable takes your
yes on the terminal; true or false decides it for every
project.

- Type: `null or boolean`
- Default: `null`

### `guards.wayland.globals`

Changes to the allowlist of Wayland globals, by interface name:
true adds one to the default list (nix/wayland.nix), false
removes one. Applied after a project's changes, so yours win.

- Type: `attribute set of boolean`
- Default: `{ }`

Example:

```nix
{
  wl_data_device_manager = true;
  zwp_pointer_constraints_v1 = false;
}
```

### `homeManager.enable`

Link the host's current home-manager generation into the volume at
each start, removing links into older ones. Off, the links of an
earlier start are removed. The home-manager module
turns this on.

- Type: `boolean`
- Default: `false`

### `hostPorts`

Host loopback ports reachable inside at 127.0.0.1, in addition to $SANDBOX_HOST_PORTS at start. For every project.

- Type: `list of string`
- Default: `[ ]`

Example:

```nix
[
  "5037"
  "8080/udp"
  "9000-9010"
]
```

### `locales`

glibcLocales build for LOCALE_ARCHIVE.

- Type: `package`
- Default: C.UTF-8 and en_US.UTF-8

### `nixConfig`

Nix settings inside, as NIX_CONFIG. The host's /etc/nix isn't bound
in (it can name access tokens), so without this nix inside runs on
defaults - no flakes, no `nix develop`.

- Type: `strings concatenated with "\n"`
- Default: `"experimental-features = nix-command flakes"`

### `nixLd.libraries`

Libraries prebuilt (non-nix) binaries find through nix-ld, which is at the dynamic loader's path (/lib64/ld-linux-x86-64.so.2 on x86_64).

- Type: `list of package`
- Default: `with pkgs; [ stdenv.cc.cc.lib zlib openssl curl libgcc ]`

### `nixProfile.enable`

Link the host's ~/.nix-profile into the volume and put its bin/ on
PATH (after the sandbox's own). Off, a link from an earlier start is
removed. The home-manager module turns this on.

- Type: `boolean`
- Default: `false`

### `package`

The `sandbox` command.

- Type: `package` (read only)

### `passEnv`

Host environment variables passed in, besides TERM, COLORTERM, LANG
and LC_ALL. Everything else is cleared.

- Type: `list of string`
- Default: `[ ]`

### `profiles`

Per-project additions, picked at start by path: binds and the guards' token commands, over the top level's.

- Type: `attribute set of (submodule)`
- Default: `{ }`

### `profiles.<name>.paths`

The profile applies when the sandbox starts in or under one of these (`~` expanded).

- Type: `list of string`
- Default: `[ ]`

### `profiles.<name>.priority`

Among profiles whose paths match, the highest priority wins.

- Type: `signed integer`
- Default: `0`

### `stateDir`

Host directory with a folder per project: its home volume, its
exchange dir and what the host keeps for it (approvals of what
projects ask for);
$XDG_DATA_HOME/sandbox (~/.local/share/sandbox) when null. `~` and
environment variables are expanded at start; $SANDBOX_STATE_DIR
overrides it.

- Type: `null or string`
- Default: `null`

## A project's sandbox

`sandbox` of `sandbox.lib.mkShell` in the project's flake.nix, which
sandboxed code can write: what reaches the host takes your yes on the
terminal first.

### `command`

What `sandbox` with no command runs, in place of a login shell.

- Type: `null or (list of string)`
- Default: `null`

Example:

```nix
[
  "nix"
  "develop"
]
```

### `git.fromHost`

Take git's name, email and ssh signing key inside from each
user's global git config on the host (`git config --global`,
run from /), where nothing more specific sets them. A user's
.sandbox.yml can turn it off (git.fromHost: false).

- Type: `boolean`
- Default: `false`

### `git.signingKey`

An ssh public key in the user's agent: git inside signs commits and tags with it. A user's .sandbox.yml wins.

- Type: `null or string`
- Default: `null`
- Example: `"ssh-ed25519 AAAA..."`

### `git.signingKeyCommand`

A shell command printing that public key, run on the host at
each start once the user approves it, like the token
commands. A user's .sandbox.yml wins.

- Type: `null or string`
- Default: `null`
- Example: `"op read \"op://Employee/GitHub SSH key/public key\""`

### `guards.claudeApiKey.tokenCommand`

A shell command that prints a Claude API key, run like
guards.github.tokenCommand. With one, Claude Code inside sends its
requests to a host proxy that adds the key - in place of logging in
inside, so not for Claude subscriptions. sandbox.lib.mkClaude's
Claude Code takes the placeholder key it needs then; another needs
`apiKeyHelper` set to `echo sandbox-placeholder`. Takes the user's yes on the terminal, asked once and again for anything new; their own config's wins.

- Type: `null or string`
- Default: `null`
- Example: `"op read op://Employee/Claude/credential"`

### `guards.forgejo.tokenCommands`

The same per Forgejo instance, by host[:port]: each command prints
that instance's token. Takes the user's yes on the terminal, asked once and again for anything new; their own config's wins.

- Type: `attribute set of string`
- Default: `{ }`

Example:

```nix
{
  "codeberg.org" = "op read op://Employee/Codeberg/token";
}
```

### `guards.github.tokenCommand`

A shell command that prints the GitHub token, e.g. from a secret
manager, run on the host at each start. With one, GitHub API
requests from inside - any gh's, or any other client's - go through
a host proxy that adds the token and holds writes for a popup. The
token is handed to the proxy in memory: never on disk, never inside
the sandbox. Without one that proxy doesn't run, and requests go
out without a token. Takes the user's yes on the terminal, asked once and again for anything new; their own config's wins.

- Type: `null or string`
- Default: `null`
- Example: `"op read op://Employee/GitHub/token"`

### `guards.wayland.enable`

Windows on the host's Wayland display, for GUI programs
inside, through a proxy that passes on only an allowlist of
the compositor's globals. Takes the user's yes on the
terminal (asked once, and again for anything new); their
own config can turn it on or off for every project.

- Type: `boolean`
- Default: `false`

### `guards.wayland.globals`

Changes to the allowlist of Wayland globals, by interface
name: true adds one to the default list, which takes the
user's yes like enable; false removes one. The user's own
changes go over these.

- Type: `attribute set of boolean`
- Default: `{ }`

Example:

```nix
{
  wl_data_device_manager = true;
}
```

### `hostPorts`

Host loopback ports reachable inside at 127.0.0.1, in addition to $SANDBOX_HOST_PORTS at start. Takes the user's yes on the terminal, asked once and again for anything new; their own config's wins.

- Type: `list of string`
- Default: `[ ]`

Example:

```nix
[
  "5037"
  "8080/udp"
  "9000-9010"
]
```

## A project's Claude Code

`claude` of `sandbox.lib.mkShell`, or `sandbox.lib.mkClaude`'s
arguments besides `pkgs`.

### `configDir`

CLAUDE_CONFIG_DIR: its login, history and state, and the
user-level settings, memory, skills and plugins it reads -
none of them a claude of your own's (home-manager's ~/.claude).
Expanded by the shell at each start. null leaves it to the
environment.

- Type: `null or string`
- Default: `"$HOME/.claude-project"`

### `lspServers`

Language servers, in a plugin of their own (--plugin-dir) that
runs each from its store path, so plugin and server are pinned
together.

- Type: `attribute set of (submodule)`
- Default: `{ }`

### `lspServers.<name>.args`

Arguments the server is started with.

- Type: `list of string`
- Default: `[ ]`

Example:

```nix
[
  "--stdio"
]
```

### `lspServers.<name>.executable`

The server's name in the package's bin/, for a package whose main
program isn't the server. The server is always that file in
`package`: never a command looked up on PATH.

- Type: `string matching the pattern [^/]+`
- Default: `package.meta.mainProgram`
- Example: `"vscode-json-language-server"`

### `lspServers.<name>.extensionToLanguage`

File extensions the server handles, with their LSP language ids.

- Type: `attribute set of string`
- Default: `{ }`

Example:

```nix
{
  ".go" = "go";
}
```

### `lspServers.<name>.package`

The language server.

- Type: `package`

### `lspServers.<name>.settings`

Server settings (workspace/configuration).

- Type: `null or JSON value`
- Default: `null`

### `mcpServers`

MCP servers, given with --mcp-config. With any, they're the only
ones (--strict-mcp-config): a .mcp.json in the project is
ignored.

- Type: `attribute set of (JSON value)`
- Default: `{ }`

### `memory`

Appended to the system prompt, after the sandbox's AGENTS.md.

- Type: `strings concatenated with "\n"`
- Default: `""`

### `package`

The Claude Code that's wrapped (unfree: the pkgs given must allow it).

- Type: `package`
- Default: `pkgs.claude-code`

### `plugins`

Plugin directories (with a .claude-plugin/plugin.json), each given with --plugin-dir.

- Type: `list of absolute path`
- Default: `[ ]`

### `settings`

Settings, given with --settings: over every settings file but
managed ones. Merged across modules.

- Type: `JSON value`
- Default: `{ }`
