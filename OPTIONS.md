# Options

Every option, with its type and default. Generated from the option
declarations in `nix/` by `make options`: change those, not this file.
The [README](README.md#configuring-the-sandbox) says what they're for.

They're the modules given to `sandbox.lib.mkSandbox`: a distribution's
own, trusted like the rest of it. Nothing here is asked about.

- [At the top level or in a profile](#at-the-top-level-or-in-a-profile)
- [The sandbox](#the-sandbox)
- [Claude Code](#claude-code)
- [Antigravity CLI](#antigravity-cli)
- [VS Code](#vs-code)

## At the top level or in a profile

A profile's (`profiles.<name>`) go over the top level's for its
projects; a profile also takes the guards' token commands.

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

## The sandbox

### `agentsMd`

/etc/sandbox/AGENTS.md: what the sandbox is and what its guards do,
for the agents inside. Claude Code's managed CLAUDE.md and the
Antigravity CLI's sandbox rules start with it. Merged across
modules: what's added goes after the sandbox's own.

- Type: `strings concatenated with "\n"`

### `etc`

Files at /etc/<name> inside, read-only: config programs read there,
out of the sandbox's reach. claude.* sets /etc/claude-code,
antigravity.adminSettings /etc/antigravity.

- Type: `attribute set of (submodule)`
- Default: `{ }`
- Example: `{ "claude-code/CLAUDE.md".text = "..."; }`

### `etc.<name>.source`

The file; `text` makes one.

- Type: `absolute path`

### `etc.<name>.text`

The file's content.

- Type: `null or strings concatenated with "\n"`
- Default: `null`

### `git.fromHost`

Take git's name, email and ssh signing key inside from your global
git config on the host (`git config --global`, run from /), where
nothing more specific sets them. A project's .sandbox.yml can turn
it off (git.fromHost: false).

- Type: `boolean`
- Default: `false`

### `guards.claudeApiKey.tokenCommand`

A shell command that prints a Claude API key, run like
guards.github.tokenCommand. With one, Claude Code inside sends its
requests to a host proxy that adds the key - in place of logging in
inside, so not for Claude subscriptions. claude.enable's Claude
Code takes the placeholder key it needs then; another needs
`apiKeyHelper` set to `echo sandbox-placeholder`. Trusted, as your config: run without asking, and it wins over a project's .sandbox.yml, whose commands run only once you approve them. A profile can set its own.

- Type: `null or string`
- Default: `null`
- Example: `"op read op://Employee/Claude/credential"`

### `guards.forgejo.tokenCommands`

The same per Forgejo instance, by host[:port]: each command prints
that instance's token. Trusted, as your config: run without asking, and it wins over a project's .sandbox.yml, whose commands run only once you approve them. A profile can set its own.

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
out without a token. Trusted, as your config: run without asking, and it wins over a project's .sandbox.yml, whose commands run only once you approve them. A profile can set its own.

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
The real socket is never bound in. Without a display on the
host, the sandbox starts without one. vscode.enable turns it on.

- Type: `boolean`
- Default: `false`

### `guards.wayland.globals`

Changes to the allowlist of Wayland globals, by interface name:
true adds one to the default list (nix/wayland.nix), false
removes one.

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
earlier start are removed. Each user's own dotfiles (and a
~/.claude of theirs, under the managed config), in every project.

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
removed. Each user's own tools, in every project.

- Type: `boolean`
- Default: `false`

### `package`

The `sandbox` command.

- Type: `package` (read only)

### `packages`

Packages on PATH inside, after the sandbox's own: the tools every
project gets, whatever its dev shell brings (which comes first on
PATH inside `nix develop`).

- Type: `list of package`
- Default: `[ ]`
- Example: `[ pkgs.gh pkgs.go-task ]`

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
exchange dir and what the host keeps for it (approvals of the
commands a project's .sandbox.yml runs);
$XDG_DATA_HOME/sandbox (~/.local/share/sandbox) when null. `~` and
environment variables are expanded at start; $SANDBOX_STATE_DIR
overrides it.

- Type: `null or string`
- Default: `null`

## Claude Code

### `claude.enable`

Whether to enable Claude Code in the sandbox, as `claude`, with managed config at /etc/claude-code.

- Type: `boolean`
- Default: `false`
- Example: `true`

### `claude.lspServers`

Language servers, in a plugin of their own (--plugin-dir) that runs
each from its store path, so plugin and server are pinned together.

- Type: `attribute set of (submodule)`
- Default: `{ }`

### `claude.lspServers.<name>.args`

Arguments the server is started with.

- Type: `list of string`
- Default: `[ ]`

Example:

```nix
[
  "--stdio"
]
```

### `claude.lspServers.<name>.executable`

The server's name in the package's bin/, for a package whose main
program isn't the server. The server is always that file in
`package`: never a command looked up on PATH.

- Type: `string matching the pattern [^/]+`
- Default: `package.meta.mainProgram`
- Example: `"vscode-json-language-server"`

### `claude.lspServers.<name>.extensionToLanguage`

File extensions the server handles, with their LSP language ids.

- Type: `attribute set of string`
- Default: `{ }`

Example:

```nix
{
  ".go" = "go";
}
```

### `claude.lspServers.<name>.package`

The language server.

- Type: `package`

### `claude.lspServers.<name>.settings`

Server settings (workspace/configuration).

- Type: `null or JSON value`
- Default: `null`

### `claude.mcpServers`

Managed MCP servers. Managed MCP config is exclusive: once any is
set, a project's own .mcp.json is ignored.

- Type: `attribute set of (JSON value)`
- Default: `{ }`

### `claude.memory`

The managed CLAUDE.md every session loads, after the sandbox's AGENTS.md (`agentsMd`).

- Type: `strings concatenated with "\n"`
- Default: `""`

### `claude.package`

The Claude Code that's wrapped (unfree: the pkgs given must allow it).

- Type: `package`
- Default: `pkgs.claude-code`

### `claude.plugins`

Plugin directories (with a .claude-plugin/plugin.json), each given with --plugin-dir.

- Type: `list of absolute path`
- Default: `[ ]`

### `claude.settings`

Managed settings (/etc/claude-code/managed-settings.json): over every
other settings file. Merged across modules.

- Type: `JSON value`
- Default: `{ }`

## Antigravity CLI

### `antigravity.adminSettings`

/etc/antigravity/admin_settings.json, agy's enterprise policy
(models, MCP, permissions, the LLM gateway): the one part of its
config the sandbox can't write. Not written when empty.

- Type: `JSON value`
- Default: `{ }`

### `antigravity.enable`

Whether to enable the Antigravity CLI in the sandbox, as `agy`, with the sandbox's rules, hooks and MCP servers in a plugin of its own.

- Type: `boolean`
- Default: `false`
- Example: `true`

### `antigravity.mcpServers`

MCP servers (mcp_config.json's `mcpServers`), in the sandbox plugin:
added to the user's and the project's own.

- Type: `attribute set of (JSON value)`
- Default: `{ }`
- Example: `{ mcp-nixos.command = lib.getExe pkgs.mcp-nixos; }`

### `antigravity.package`

The Antigravity CLI that's wrapped (unfree: the pkgs given must allow it).

- Type: `package`
- Default: `pkgs.antigravity-cli`

### `antigravity.plugins`

Plugin directories (with a plugin.json), each linked at
~/.gemini/config/plugins/sandbox-<name>.

- Type: `attribute set of absolute path`
- Default: `{ }`
- Example: `{ team = ./antigravity-plugin; }`

### `antigravity.rules`

Rules every session loads, after the sandbox's AGENTS.md (`agentsMd`): the sandbox plugin's rules/AGENTS.md.

- Type: `strings concatenated with "\n"`
- Default: `""`

### `antigravity.settings`

Settings given with --settings at every run: over
~/.gemini/antigravity-cli/settings.json, for that run only, never
saved. Merged across modules. `enableTerminalSandbox` defaults to
false: agy's own sandbox for commands needs nested namespaces, which
the sandbox blocks, so each command would fail there before agy
retried it outside.

- Type: `JSON value`
- Default: `{ }`

Example:

```nix
{
  agentMode = "accept-edits";
}
```

## VS Code

### `vscode.args`

Arguments it's always started with. The default skips the workspace
trust prompt, which keeps extensions off until it is answered: the
sandbox is the boundary.

- Type: `list of string`

Default:

```nix
[
  "--disable-workspace-trust"
]
```

### `vscode.enable`

Whether to enable VS Code in the sandbox, as `code`, with the Wayland guard on.

- Type: `boolean`
- Default: `false`
- Example: `true`

### `vscode.extensions`

Extensions, built in (vscode-with-extensions): pinned like the rest, none installed into the volume by hand.

- Type: `list of package`
- Default: `[ ]`
- Example: `[ pkgs.vscode-extensions.anthropic.claude-code ]`

### `vscode.fonts`

Fonts for its fontconfig: the sandbox has no host fonts.

- Type: `list of package`
- Default: `[ pkgs.dejavu_fonts pkgs.noto-fonts-color-emoji ]`

### `vscode.package`

VS Code (unfree: the pkgs given must allow it).

- Type: `package`
- Default: `pkgs.vscode`
