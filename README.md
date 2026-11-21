# sandbox

Run coding agents (Claude Code included) and untrusted project builds in a
per-project Linux sandbox: bubblewrap + pasta + seccomp, with every program
inside and outside coming from nix - nothing from the host's `/usr`.

```sh
cd ~/src/some-project
nix run github:mgnsk/sandbox                        # a login shell in the sandbox
nix run github:mgnsk/sandbox -- nix develop -c claude   # Claude Code, from the project's dev shell
```

With an alias (see [Install](#install)), that's `sandbox`,
`sandbox nix develop -c claude`, `sandbox nix develop -c make`, ...

Requirements: Linux with unprivileged user namespaces, and nix with a daemon
(a multi-user install). Popups need the sandbox started from a terminal,
local or over ssh; without one every guarded request is refused. On Ubuntu
23.10 and later, see [Troubleshooting](#troubleshooting).

What you get, per project:

- **Its own `$HOME`**, kept between runs in `~/.local/share/sandbox`, one
  folder per project.
- **Your project, read-write**: the git work tree you start in (or just the
  current directory outside a repo). Nothing else of your home is visible
  unless you bind it in.
- **No host userland, and few tools of its own**: a shell, nix, git and
  [the basics](#where-tools-come-from). Everything else, Claude Code
  included, comes from the project's dev shell.
- **Nix builds** through the host's daemon (`/nix` is read-only inside).
- **Network** out, but not to the host's own services, except the ports you
  open: `hostPorts`, or `SANDBOX_HOST_PORTS="5037 8080/udp"` for one run.
  Ports bound inside are reachable from the host's `127.0.0.1` (dev servers,
  OAuth callbacks).
- **Guarded host access**: credentials stay outside, and what could act on
  your behalf waits for a popup on the terminal the sandbox runs in.

  | Guard | What it gives the inside | Asks |
  | --- | --- | --- |
  | [ssh agent](#ssh-agent) | your agent's keys, never the socket | for every signature but git's with your signing key |
  | [GitHub API](#github-and-forgejo) | `gh` or any client, on a token from a token command | for writes |
  | [Forgejo APIs](#github-and-forgejo) (opt-in) | the same, per instance | for writes |
  | [Claude API](#claude-code) (opt-in) | Claude Code on an API key held outside | never |
  | open URL | `xdg-open` for http(s) URLs, in the host's browser | always |
  | [Wayland](#wayland) (opt-in) | windows on your display, through a filtering proxy | never |
  | Secret Service | libsecret for tools inside, kept apart per project in your keyring | never |

  A popup takes `y` (once), `A` (always, in this sandbox), `N` (no, the
  default) or `D` (never, in this sandbox).
- **An exchange dir** (`$SANDBOX_EXCHANGE`), read-only inside, for output of
  commands you run on the host.
- **Claude Code** with managed settings and a `CLAUDE.md` that tells it about
  all of the above.

See [SECURITY.md](SECURITY.md) for the threat model, and for what the
sandbox doesn't protect against.

## Install

Pick one of two ways to get a `sandbox` command:

- **From this repo, with default settings** - nothing to install, just an
  alias in your shell config:

  ```sh
  alias sandbox='nix run github:mgnsk/sandbox --'
  ```

  It reads no config of yours; the repo you work on adjusts what applies
  inside through its [sandbox.nix](#the-projects-sandboxnix), and you through
  your [.sandbox.yml](#per-user-project-settings-sandboxyml) there.
- **Your home-manager config**, with settings of your own for every
  project (see [Your sandbox config](#your-sandbox-config)). The only way to
  change what applies on the host: `passEnv`, the ssh agent socket and guard,
  profiles, ...

`sandbox` in the rest of this README is whichever of these you use.

`github:mgnsk/sandbox` follows this repo's default branch, cached for up to
an hour (`nix run --refresh` fetches it now). To update only when you choose
to, pin a commit you reviewed, and optionally its hash, which nix then
checks the fetched tarball against:

```sh
alias sandbox='nix run github:mgnsk/sandbox/<rev> --'
alias sandbox="nix run 'github:mgnsk/sandbox/<rev>?narHash=sha256-...' --"
nix flake metadata --json github:mgnsk/sandbox/<rev> | jq -r .locked.narHash
```

Always run the remote, never a clone of this repo that a sandbox can write:
the launcher runs on the host, and a checkout holds whatever sandboxed code
put there.

## Using it in a project

Say a project has just a `flake.nix` with a dev shell:

```nix
{
  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        # claude-code is unfree.
        config.allowUnfreePredicate = p: nixpkgs.lib.getName p == "claude-code";
      };
    in {
      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [
          pkgs.claude-code pkgs.gh   # the sandbox ships neither
          pkgs.go pkgs.gopls pkgs.golangci-lint
        ];
        CGO_ENABLED = "0";           # the project's variables go here too
      };
    };
}
```

Start the sandbox in the project and enter the dev shell inside it:

```sh
cd ~/src/myproject
sandbox nix develop                    # interactive dev shell
sandbox nix develop -c claude          # Claude Code with the project's tools on PATH
sandbox nix develop -c go test ./...   # a one-off command
```

`command = [ "nix" "develop" ];` in the project's
[sandbox.nix](#the-projects-sandboxnix) makes the dev shell what a bare
`sandbox` runs. With direnv, `use flake` in `.envrc` does the same whenever
you `cd` in.

### Where tools come from

The sandbox's own `PATH` is fixed, and no configuration adds to it: bash,
nix, git (with `less` and `nano`, its pager and editor), ssh, the
coreutils/grep/sed/tar/make set that `nix develop` adds anyway, and `jq`,
`curl`, `rg`, `which`, `ps`/`pgrep`/`pkill`, `zip` and `unzip`. `/bin/sh`,
`/usr/bin/env` and nix-ld for prebuilt binaries are provided.

Everything else comes from:

- **the project's dev shell** (a flake's `devShells`, devenv): its tools -
  Claude Code, gh, fj, linters, direnv - and its environment variables;
- **your own profile**: `~/.nix-profile` and home-manager, for the tools
  and dotfiles you want in every project. Only a sandbox installed through
  [home-manager](#your-sandbox-config) links these in; `nix run
  github:mgnsk/sandbox` doesn't, so that everyone gets the same environment
  there. The rest of this README calls this "your own profile".

### The project's `$HOME`

`~/go/pkg`, `~/.cache`, Claude's `~/.claude`, ... persist between runs and
aren't shared with other projects. From your real home it gets only what's
bound in (`binds`) and your own profile.

- **Shell startup.** The sandbox has a managed, read-only `/etc/bashrc` and
  `/etc/profile`, which bash reads before your own files: every interactive
  shell loads bash-completion (also at `/usr/share/bash-completion`), and
  the prompt is `user@project:directory$` where it would be bash's bare
  default - the host name inside is the project's directory name. Your
  `.bashrc`/`.bash_profile` run after them and can override anything.
- **Git identity.** That `$HOME` starts without a `~/.gitconfig`, so unless
  your own profile brings one, set `git.fromHost` (name, email and signing
  key from your host's global git config) or `git.userName`/`git.userEmail`
  in the project's [.sandbox.yml](#per-user-project-settings-sandboxyml);
  `sandbox.nix` can set `git.fromHost` for everyone. `git config --global`
  inside is saved in that project's `$HOME` only.

### Using devenv

[devenv](https://devenv.sh) runs inside the sandbox like any other tool:
`devenv.nix` and `devenv.yaml` stay as they are, and its shell, scripts,
tasks, processes and services all run sandboxed. devenv itself comes from
your own profile, or from the project:

```nix
# sandbox.nix, next to devenv.nix
{
  command = [ "devenv" "shell" ];   # a bare `sandbox` enters the devenv shell
}
```

```sh
sandbox                                  # devenv shell
sandbox devenv up                        # processes and services
sandbox devenv shell -- claude           # Claude Code with devenv's tools on PATH
```

A project can also bring its own devenv, pinned in its `flake.lock`
(`packages.<system>.devenv = devenv.packages.<system>.devenv;` in its
flake), with `command = [ "nix" "run" ".#devenv" "--" "shell" ];`.
`sandbox nix run nixpkgs#devenv -- shell` works too, unpinned.

What to know:

- **Services are inside.** A Postgres or Redis from `services.*` runs in the
  sandbox, so the project reaches it on `127.0.0.1` without `hostPorts`
  (that's for services on the host).
- **Each sandbox has its own network**, so services from `devenv up` in one
  sandbox aren't on `127.0.0.1` in another of the same project. Run
  everything in one sandbox (`devenv up -d`, then `claude`; or tmux), or
  reach them from a second one through the host, where the first one's
  ports already show up:

  ```sh
  sandbox devenv up                                               # first: services
  SANDBOX_HOST_PORTS="5432 6379" sandbox devenv shell -- claude   # second
  ```

  Pass them only to the second sandbox, never through `hostPorts`, which
  applies to both: the first one's port would be held for the forward.
- **Containers: build inside, run elsewhere.** `devenv container build` is
  a nix build, so it works; running the image doesn't (no Docker daemon
  inside, and rootless podman needs the user namespaces the sandbox
  blocks). Push to a registry from inside, or write an archive into the
  project (`--registry oci-archive:`) and `docker load` it on the host.
  Never give the sandbox `/var/run/docker.sock` or a daemon port: the Docker
  API is root on the host.
- **Binary caches** from `cachix.pull` need the nix daemon to trust you.
  Don't add yourself to `trusted-users` for it (see
  [SECURITY.md](SECURITY.md#nix-daemon)); add the caches to the daemon's own
  config (`extra-substituters`, `extra-trusted-public-keys`).
- **Not on the host.** Don't enable devenv's `cd` hook or direnv's `use
  devenv` on the host for a sandboxed project: both run devenv.nix outside
  the sandbox, and the sandbox can edit it.

## Configuring the sandbox

### Where settings go

| Where | What it can set | Trust |
| --- | --- | --- |
| **Your sandbox config**: home-manager's `programs.sandbox.settings` | Every [option](#options), including `profiles` | Trusted: applies without asking, and wins over the project's settings |
| **The project's [`sandbox.nix`](#the-projects-sandboxnix)**, committed | `command`, `claude.*`, `hostPorts`, `binds`, the guards' token commands, `guards.wayland`, `git.fromHost`, `git.signingKey`, `git.signingKeyCommand` | Sandboxed code can edit it: what reaches the host is **approved** first |
| **The project's [`.sandbox.yml`](#per-user-project-settings-sandboxyml)**, gitignored, each user's own | The guards' token commands and `git.*` | As `sandbox.nix`, which it overrides |
| **The project's dev shell** | Tools and the project's environment variables | Runs inside |

**Approved** means: binds, host ports, the Wayland guard and commands run on
the host are shown on the terminal and apply only after your yes. It's asked
the first time, and again only if they change. Everything else a project
sets only affects the inside and applies without asking.

### The project's sandbox.nix

A `sandbox.nix` in the project root configures the sandbox around the
project, on top of your config - like `devenv.nix`, a module that gets
`pkgs`:

```nix
{ pkgs, lib, ... }:
{
  # What a bare `sandbox` runs, in place of a login shell.
  command = [ "nix" "develop" ];

  # Approved: host ports reachable at 127.0.0.1 inside (port, port/udp or a
  # range), and host paths bound in - absolute, and outside the project.
  hostPorts = [ "5432" "9000-9010" ];
  binds = [
    { src = "~/datasets"; }                                  # read-only, same path
    { src = "~/src/shared-lib"; hideGit = true; }            # for reference, without its history
    { src = "~/notes/myproject"; dst = "~/notes"; mode = "rw"; optional = true; }
  ];

  # Approved: commands printing the API tokens, and windows on the user's
  # Wayland display. See Guards below.
  guards.github.tokenCommand = "op read op://Employee/GitHub/token";
  guards.wayland.enable = true;

  # Git inside: identity and signing key from each user's host git config.
  git.fromHost = true;

  claude = {
    # Over your managed settings: objects merge, lists add up, the rest is replaced.
    settings.permissions.allow = [ "Bash(go test:*)" ];
    # Appended to the managed CLAUDE.md.
    memory = ''
      Run `go test ./...` before calling a change done.
    '';
    # Managed MCP servers: once any is set, the project's .mcp.json is ignored.
    mcpServers.mcp-nixos = { type = "stdio"; command = lib.getExe pkgs.mcp-nixos; };
    # See Plugins and language servers.
    lspServers.gopls = { package = pkgs.gopls; extensionToLanguage.".go" = "go"; };
  };
}
```

`pkgs` is the sandbox's own nixpkgs. For the project's pinned one, import it
yourself: `(builtins.getFlake (toString ./.)).inputs.nixpkgs.legacyPackages.${pkgs.stdenv.hostPlatform.system}`.

How it stays a sandbox, though the sandbox can edit the file:

- **It's evaluated in a sandbox** of its own, never on the host. The result
  is cached until `sandbox.nix`, your sandbox config or the profile changes;
  `sandbox --reload` picks up changes in files it imports, and
  `sandbox --no-project-config` ignores it (and `.sandbox.yml`).
- **The `sandbox` command and everything that runs on the host stay yours**:
  bwrap, pasta, seccomp, the guards and their settings come from your
  sandbox config, never from the project.
- **What reaches the host is approved**, as above.

### Per-user project settings: .sandbox.yml

`sandbox.nix` is the project's, committed. What differs per user - the
token commands' secret-manager items, the git identity - goes in a
`.sandbox.yml` next to it, which the project gitignores (ship a
`.sandbox.example.yml` for reference). Its settings have `sandbox.nix`'s
option names, every one is optional, and an unknown field stops the start:

```yaml
# .sandbox.yml - mine, not committed
guards:
  github:
    tokenCommand: op read op://Employee/GitHub/token
  forgejo:
    tokenCommands:
      codeberg.org: op read op://Employee/Codeberg/token
  claudeApiKey:
    tokenCommand: op read op://Employee/Claude/credential
git:
  fromHost: true          # name, email and signing key from the host's git config
  userName: Some One
  userEmail: some.one@example.com
  signingKeyCommand: op read "op://Employee/GitHub SSH key/public key"
  # or signingKey: ssh-ed25519 AAAA...
```

- **Token commands** go over `sandbox.nix`'s, and are approved like them:
  sandboxed code can write this file too. Your own config's still win.
- **`git.userName`, `git.userEmail`**: git's author and committer inside.
- **`git.signingKey`**: an ssh public key in your agent; commits and tags
  inside are signed with it (`gpg.format = ssh`), through the ssh agent
  guard, which doesn't ask for those. **`git.signingKeyCommand`** prints
  that key on the host at each start instead, so it's approved. Either
  replaces both of `sandbox.nix`'s.
- **`git.fromHost`**: fill in what isn't set from your global git config on
  the host - `user.name`, `user.email` and, with `gpg.format = ssh`,
  `user.signingKey` (the key, or a key file whose `.pub` is read). Here it
  can also turn `sandbox.nix`'s `git.fromHost` off.

The git settings are git config from the environment, so they override
`~/.gitconfig` inside.

### Your sandbox config

Your own sandbox config comes from your home-manager config, never from a
project. `programs.sandbox.settings` is a module with the
[options](#options) below, given your home-manager `pkgs`. Its top level
applies to every project; [profiles](#profiles) narrow some settings to
projects under given paths.

```nix
modules = [
  inputs.sandbox.homeManagerModules.default
  {
    programs.sandbox.enable = true;
    programs.sandbox.settings = {
      passEnv = [ "EDITOR" ];
      guards.openUrl.enable = false;
      profiles.work = {
        paths = [ "~/work" ];
        guards.claudeApiKey.tokenCommand = "op read op://Employee/Claude/credential";
      };
    };
  }
];
```

Updating is updating the flake input your home-manager config takes it from,
then switching.

Only the sandbox installed this way brings your own profile in: it links
your current home-manager generation into each project's `$HOME` at every
start (`homeManager.enable`), and your `~/.nix-profile`
(`nixProfile.enable`), with its `bin/` on `PATH`. A project has one `$HOME`
whichever sandbox starts it, so a start with `nix run github:mgnsk/sandbox`
removes those links, and your next start with your own links them again.

### Options

The options of your sandbox config; all are in [nix/module.nix](nix/module.nix).

| Option | Default | |
| --- | --- | --- |
| `passEnv` | `[ ]` | Host variables passed in, besides TERM/COLORTERM/LANG/LC_ALL; everything else is cleared. |
| `binds` | `[ ]` | Host paths bound in: `{ src; dst; mode = "ro" \| "rw"; optional; hideGit; }`; `~`, `$HOME`, `$USER`, `$XDG_RUNTIME_DIR` expanded in `src`. One whose src is the project is left to the project bind. |
| `hostPorts` | `[ ]` | Like `SANDBOX_HOST_PORTS`, always. |
| `stateDir` | `$XDG_DATA_HOME/sandbox` | One folder per project: its `$HOME`, exchange dir, `sandbox.nix` approvals and cache. `$SANDBOX_STATE_DIR` overrides. |
| `nixLd.libraries` | libstdc++, zlib, openssl, curl, libgcc | For prebuilt binaries. |
| `nixConfig` | flakes on | `NIX_CONFIG` inside; there is no nix.conf in there. |
| `nixProfile.enable` | off (on with the home-manager module) | Link the host's `~/.nix-profile` in and put its `bin/` on `PATH`, after the sandbox's own. |
| `homeManager.enable` | off (on with the home-manager module) | Link your current home-manager generation into each project's `$HOME` at every start. |
| `locales` | C.UTF-8, en_US.UTF-8 | glibcLocales build for `LOCALE_ARCHIVE`; override to add yours. |
| `guards.sshAgent` | on | `enable`, `socket` (the host agent's; `$SSH_AUTH_SOCK` at start) and `path` (inside; `$XDG_RUNTIME_DIR/ssh-agent.sock`). See [SSH agent](#ssh-agent). |
| `guards.github.tokenCommand` | none | A shell command printing the token, run on the host at each start. See [GitHub and Forgejo](#github-and-forgejo). |
| `guards.forgejo.tokenCommands.<host>` | `{ }` | The same per Forgejo host. |
| `guards.claudeApiKey.tokenCommand` | none | A shell command printing a Claude API key: Claude Code then runs on it, held outside. See [Claude Code](#claude-code). |
| `guards.openUrl.enable` | on | `xdg-open` inside opens http(s) URLs in the host's browser, after a popup. |
| `guards.secretService.enable` | on | A per-project Secret Service for tools using libsecret, storing in the host's (gnome-keyring, KeePassXC, ...). Without one on the host the sandbox doesn't start: turn this off then. |
| `guards.notifications.enable` | on | With a Wayland display inside, show a popup as a desktop notification too. See [Popups from a window](#popups-from-a-window). |
| `guards.wayland.enable` | `null` | Windows on your Wayland display: `true` or `false` for every project, `null` to leave it to each project's `sandbox.nix`. See [Wayland](#wayland). |
| `guards.wayland.globals.<name>` | `{ }` | Changes to the allowlist of Wayland globals: `true` adds one, `false` removes one. Yours go over a project's. |
| `claude.enable` | on | Claude Code's managed config at `/etc/claude-code`, for the `claude` your dev shell or profile brings. |
| `claude.settings` | autoupdater off, hooks steering GitHub HTTP requests to `gh` and denying `gh`/`fj` logins | managed-settings.json, merged across modules. |
| `claude.memory` | sandbox, GitHub, Forgejo notes | Managed CLAUDE.md; your lines are appended. |
| `claude.mcpServers` | `{ }` | Managed MCP servers (exclusive: a project's .mcp.json is then ignored). |
| `claude.lspServers.<name>` | `{ }` | `{ package; executable; args; extensionToLanguage; settings; }`, see below. |
| `claude.marketplaces.<name>` | `{ }` | Plugin marketplace directories (store paths). |
| `profiles.<name>` | `{ }` | Per-project additions, see [Profiles](#profiles). |

A project's `sandbox.nix` can set `binds`, `hostPorts`, `claude.*` (except
`enable`), the token commands and `guards.wayland` too, and `command` and
`git.*`, which are only its own and `.sandbox.yml`'s.

### Plugins and language servers

Plugins come from marketplaces in the store, pinned like everything else,
not from git checkouts that update themselves in each project's `$HOME`.
In your sandbox config, a profile or a project's `sandbox.nix`:

```nix
claude.lspServers = {
  gopls = { package = pkgs.gopls; extensionToLanguage.".go" = "go"; };
  # A package whose main program isn't the server: name it in its bin/.
  json = {
    package = pkgs.vscode-langservers-extracted;
    executable = "vscode-json-language-server";
    args = [ "--stdio" ];
    extensionToLanguage.".json" = "json";
  };
};
claude.marketplaces.mine = ./my-marketplace;   # .claude-plugin/marketplace.json
claude.settings.enabledPlugins."some-plugin@mine" = true;
```

A language server is always `package`'s `bin/<executable>` (default: its
`meta.mainProgram`), never a command on `PATH`, and is an enabled plugin of
a generated marketplace. Once any marketplace or language server is set,
these are the only marketplaces Claude Code knows: the official one and
`/plugin marketplace add` are refused.

### Profiles

Profiles are only in your sandbox config. A profile applies when the sandbox
starts under one of its `paths`, or in a project whose root has one of its
`projectFiles`. Only one applies: the matching one with the highest
`priority` (the first by name on a tie). It adds `binds` and `claude.*` on
top of the top level, and can set its own token commands; everything else
is top-level only.

A profile with `projectFiles` can only set `claude.*`: sandboxed code can
create the file, so binds and token commands go in a profile picked by
`paths` alone.

```nix
programs.sandbox.settings = { lib, pkgs, ... }: {
  profiles.flake = {
    projectFiles = [ "flake.nix" ];
    claude.mcpServers.mcp-nixos = { type = "stdio"; command = lib.getExe pkgs.mcp-nixos; };
  };
  profiles.audio = {
    paths = [ "~/src/audio" ];
    priority = 20;
    binds = [ { src = "~/Samples"; optional = true; } ];
  };
};
```

## Guards

### GitHub and Forgejo

> [!WARNING]
> **Never run `gh auth login` or `fj auth login` inside the sandbox.** A
> token stored inside is readable by everything that runs there, and
> requests made with it skip the host proxy and its write popups. If you
> already logged in inside, run `gh auth logout` / `fj auth logout` there
> and revoke that token. The sandbox blocks the usual ways in and warns at
> each start of a login it finds stored inside; a token pasted in by hand
> still can't be stopped.

gh and fj talk to their APIs through host proxies that add a token to each
request, and hold writes for a popup that shows what would be written. The
token never enters the sandbox and is never written to disk: a **token
command** prints it on the host at each start - typically your secret
manager - and it's handed to the proxy in memory. gh or fj on the host, and
any login they have, are never used.

```nix
guards.github.tokenCommand = "op read op://Employee/GitHub/token";
guards.forgejo.tokenCommands."codeberg.org" = "op read op://Employee/Codeberg/token";
```

- **Where**: the project's `sandbox.nix` (for everyone working on it) or
  your `.sandbox.yml` there, both approved; or your own sandbox config,
  trusted, where a [profile](#profiles) can set them for the projects it
  matches. Yours win.
- **How it runs**: from `/`, with your terminal (so `op` can ask you to
  unlock it) and your `PATH`. If it fails or prints no token, the sandbox
  doesn't start. A new token takes a restart.
- **Without one** the guard doesn't run, and requests to that API go out
  without a token. The guards have no switch of their own.
- **Which token**: for GitHub, a
  [fine-grained token](https://github.com/settings/personal-access-tokens/new)
  limited to the project's repositories: typically read-only Contents and
  Actions, read-write Issues and Pull requests. Pushes go over ssh, so it
  needn't write Contents. `gh auth token` works as a command too, when
  you're logged in with gh on the host, but that token is your whole GitHub
  login.

The sandbox ships neither gh nor fj: bring them like any other tool.
Whichever runs reaches the guards through `HTTPS_PROXY`, which every process
inside gets once a token command is set; clients that ignore it reach the
APIs without a token. [SECURITY.md](SECURITY.md#the-router) has the
mechanism.

### Claude Code

By default Claude Code is logged in per project, inside the sandbox: start
it (`sandbox nix develop -c claude`), pick the login method, and allow the
popup that opens the login URL in the host's browser (or copy the link).
Every new project needs this once. Code running in that sandbox can read
the login (see [SECURITY.md](SECURITY.md#claude-code-a-login-inside-or-an-api-key-outside)).

**On an API key**, the key stays on the host and a proxy adds it to Claude
Code's requests. It's a token command like GitHub's:

```nix
guards.claudeApiKey.tokenCommand = "op read op://Employee/Claude/credential";
```

Create a key for the project at
[platform.claude.com](https://platform.claude.com/settings/keys), ideally in
a workspace with a spend limit, store it in your secret manager, set the
command and run `claude` inside as usual - no login. Deleting the key in the
Console cuts off just that project. If the project was logged in inside
before, run `/logout` there so that login doesn't stay in the volume.

A subscription login can't go through the proxy: Anthropic doesn't allow
tools to hold claude.ai credentials. A [profile](#profiles) can set the
command, so some projects use a key while others log in.

### SSH agent

The ssh agent guard proxies whichever agent `$SSH_AUTH_SOCK` points to when
the sandbox starts (`guards.sshAgent.socket` to pick another). Inside, only
the guard's proxy is visible, never the real socket. A sign request (an ssh
login, `git push` over ssh) gets the sandbox's popup first, except git
commit and tag signatures with your signing key: `git.signingKey`, or the
`user.signingKey` of your global git config on the host. With any other key
in the agent a git signature asks too. The agent's own approval, if it has
one, still applies on top.

Your `~/.ssh/config` isn't there inside, only your `known_hosts`
(read-only). Without home-manager's `programs.ssh`, bind it in with
`binds = [ { src = "~/.ssh/config"; } ];`. Keys stay in the agent:
`IdentityFile` lines naming private keys find nothing inside, but a public
key there still picks the agent key to use, if you bind that `.pub` file in
too.

**1Password**: its agent is `~/.1password/agent.sock`; with `SSH_AUTH_SOCK`
set to that on the host, the defaults work. `gpg.ssh.program = op-ssh-sign`
and the `op` CLI's desktop app integration don't work inside (both need the
app, which isn't reachable): sign through the agent
(`gpg.format = ssh` with the public key as `user.signingKey`), and use `op`
on the host, in token commands.

### Wayland

Off by default: without it there is no display inside, and no GUI programs.
With `guards.wayland.enable` - in a `sandbox.nix` (approved) or your own
config - programs inside open windows on your Wayland display:

```nix
guards.wayland.enable = true;
```

Inside, `WAYLAND_DISPLAY` is `wayland-0`, a socket of the sandbox's own.
Your compositor's real socket is never bound in. The guard is a proxy on the
host, [wl-veil](https://github.com/mahkoh/wl-proxy), which passes on only an
allowlist of the compositor's globals - by default what a program needs to
show and drive its own windows ([nix/wayland.nix](nix/wayland.nix)).
[SECURITY.md](SECURITY.md#wayland-a-proxy-with-an-allowlist-never-the-socket)
says what the real socket would give away.

**The clipboard is off by default.** With it, a window inside reads what
you last copied on the host whenever it has the keyboard focus. So copy and
paste between the host and a program inside doesn't work, and some programs
(foot) don't start. Add it where you want that:

```nix
guards.wayland.globals = {
  wl_data_device_manager = true;                   # clipboard, drag-and-drop
  zwp_primary_selection_device_manager_v1 = true;  # the primary selection
  zwp_pointer_constraints_v1 = false;              # or take one off the list
};
```

The allowlist is the defaults, then the project's changes, then your own
config's: yours win. A global a project adds is approved; one it removes
isn't asked about.

What the sandbox doesn't have, with or without the guard: a GPU (programs
render in software), X11, and the host's fonts or fontconfig - the dev shell
brings those.

#### Popups from a window

The guards' popups are drawn on the terminal the sandbox runs on, which you
aren't looking at while you work in a window. So in a sandbox with a Wayland
display, a request is shown as a desktop notification as well - Deny, Allow
once, Always in this sandbox - unless it comes from a program on the
sandbox's own terminal.

- The popup on the terminal stays: whichever is answered first counts.
  Closing the notification without picking an answer is a no.
- A long request is cut in the notification, which says so; the whole of it
  is on the terminal. Answering from the notification approves the request
  as it is, not only what the notification shows.
- It needs a notification daemon that advertises actions (tried with
  swaync); without one the launcher says so at start and asks on the
  terminal only.

`guards.notifications.enable = false;` in your sandbox config turns it off.

## Troubleshooting

- **Ubuntu 23.10 and later: bwrap can't create a user namespace.** AppArmor
  blocks unprivileged user namespaces for programs without a profile, which
  includes bwrap from the nix store. Write an AppArmor profile allowing
  `userns` for that store path, or turn the restriction off with
  `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0` (in
  `/etc/sysctl.d/` to keep it) - which drops that hardening for every
  program on the host.
- **"refusing to run in ..."**: the project would cover host state - your
  home, a dot directory of it, `/tmp`, `$XDG_RUNTIME_DIR`. Start in a
  project directory of its own.
- **"Author identity unknown"** on the first commit: see
  [Git identity](#the-projects-home).
- **Commit signing asks every time**: the key isn't one the sandbox knows as
  git's. See [SSH agent](#ssh-agent).
- **`ssh` or `git push` uses no agent**: your shell config sets
  `SSH_AUTH_SOCK` unconditionally (home-manager session variables, say),
  over the guard's. Keep a value that's already set
  (`home.sessionVariables.SSH_AUTH_SOCK = "\${SSH_AUTH_SOCK:-$HOME/.1password/agent.sock}";`),
  or put the proxy where your config points
  (`guards.sshAgent.path = "~/.1password/agent.sock";`).
- **The sandbox doesn't start: no Secret Service** on the host. Set
  `guards.secretService.enable = false`.
- **"address in use" for a service inside**: its port is in `hostPorts` or
  `SANDBOX_HOST_PORTS` of the same sandbox, and so held for the forward.
- **gh has no access**: no token command is set. See
  [GitHub and Forgejo](#github-and-forgejo).
- **TLS errors from a pip-installed `certifi`**: the guards' CAs are in the
  system bundle and the usual variables (`SSL_CERT_FILE`, ...), which code
  calling `certifi.where()` itself doesn't read.
- **Chromium and Electron programs** need `--no-sandbox` (their own sandbox
  wants user namespaces) and `--ozone-platform=wayland`.
- **A `sandbox.nix` change in an imported file isn't picked up**:
  `sandbox --reload`.

## Development

```sh
make test              # everything: nix checks, all tests against a fresh build, and lint
make test RUN=HostPort # only the tests matching a go test -run filter, no lint
make coverage          # line coverage of the Go code by the tests
make fmt               # format Go and nix files
make vuln              # known vulnerabilities the Go code reaches
make vendor-hash       # after a go.mod change: the modules' hash in nix/go.nix
make demo-flake        # a fresh user in a container: a project with flake.nix and sandbox.nix
make demo-home-manager # the same with the sandbox from a home-manager config
```

The demos ([demo/](demo)) run on the host, in Docker, and take the sandbox
from `github:mgnsk/sandbox` like `nix run` does, not from the checkout.

The launcher, init and the guards are subcommands of one Go binary,
`sandbox-bin` (`cmd/sandbox-bin`, `internal/`); `sandbox-bin --help` lists
them, and the `sandbox` command is a wrapper around `sandbox-bin launch`
with its configuration, which nix builds from the options
(`nix/module.nix`). Each package has its tests next to it; the launcher's
and init's also run the binary's subcommands, and `e2e/` starts real
sandboxes from a fresh build.

Each target enters the dev shell itself when run outside it. The
real-sandbox tests need unprivileged user namespaces, so they skip inside a
running sandbox: run `make test` on the host for the full suite.
