# sandbox

Run coding agents (Claude Code included) and untrusted project builds in a
per-project Linux sandbox: bubblewrap + pasta + seccomp, with every program
inside and outside coming from nix - nothing from the host's `/usr`.

This repo is a library: an organisation builds one `sandbox` command from
it - the tools everyone gets inside, the guards, Claude Code's managed
config - and its people install that like any other tool. It works the same
in every project, whatever the project has.

```sh
cd ~/src/some-project
sandbox                  # a login shell in the sandbox
sandbox claude           # Claude Code, with the distribution's managed config
sandbox code .           # VS Code, its window on your Wayland display
sandbox nix develop      # the project's own dev shell, inside
```

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
- **No host userland**: a shell, nix, git and [the basics](#where-tools-come-from),
  the distribution's tools, and the project's dev shell.
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
  | [Claude API](#claude-api-key) (opt-in) | Claude Code on an API key held outside | never |
  | open URL | `xdg-open` for http(s) URLs, in the host's browser | always |
  | [Wayland](#wayland) (opt-in) | windows on your display, through a filtering proxy | never |
  | Secret Service | libsecret for tools inside, kept apart per project in your keyring | never |

  A popup takes `y` (once), `A` (always, in this sandbox) or `N` (no, the
  default). For an ssh login whose popup names its server, `A` covers that
  server alone.
- **An exchange dir** (`$SANDBOX_EXCHANGE`), read-only inside, for output of
  commands you run on the host.
- **Claude Code and VS Code** if the distribution turns them on, with
  managed config that sandboxed code can't change, and an
  `/etc/sandbox/AGENTS.md` that tells agents about all of the above.

See [SECURITY.md](SECURITY.md) for the threat model, and for what the
sandbox doesn't protect against.

## Install

A distribution is a flake that builds `sandbox` with `lib.mkSandbox` from
configuration [modules](#configuring-the-sandbox):

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    sandbox.url = "github:mgnsk/sandbox";
    sandbox.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, sandbox, ... }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        # Claude Code and VS Code are unfree.
        config.allowUnfreePredicate = p: builtins.elem (nixpkgs.lib.getName p) [ "claude-code" "vscode" ];
      };
    in {
      packages.x86_64-linux.sandbox = sandbox.lib.mkSandbox {
        inherit pkgs;
        modules = [
          {
            packages = [ pkgs.gh ];
            git.fromHost = true;
            claude.enable = true;
            vscode.enable = true;
          }
        ];
      };
    };
}
```

Its users install it like any other tool - `nix profile add <flake>#sandbox`,
or `home.packages` - and update it by updating the distribution. The demo
(`make demo`, [demo/distribution](demo/distribution)) is one.

The distribution's `flake.lock` pins this repo: update it to a commit you
reviewed. Build and install from a checkout no sandbox can write: the
launcher runs on the host, and a checkout holds whatever sandboxed code put
there (see [SECURITY.md](SECURITY.md#where-the-configuration-comes-from)).

## Using it in a project

```sh
cd ~/src/myproject
sandbox                        # a login shell
sandbox nix develop            # the project's dev shell, inside
sandbox nix develop -c claude  # Claude Code with the dev shell's tools on PATH
sandbox code .                 # VS Code
```

A project needs nothing for it: the sandbox is the distribution's, the
same in every project. A dev shell of its own adds its tools inside, on top
of the distribution's. Don't enter that shell on the host (`nix develop`,
direnv's `use flake`): the sandbox can edit the flake, and the host would
run it.

### Where tools come from

The sandbox's base `PATH`: bash, nix, git (with `less` and `nano`, its pager
and editor), ssh, the coreutils/grep/sed/tar/make set that `nix develop`
adds anyway, and `jq`, `curl`, `rg`, `which`, `ps`/`pgrep`/`pkill`, `zip`
and `unzip`. `/bin/sh`, `/usr/bin/env` and nix-ld for prebuilt binaries are
provided.

On top of it:

- **the distribution's `packages`**, in every project: `claude` and `code`
  when it turns those on, gh, ...;
- **the project's dev shell** (a flake's `devShells`, devenv), first on
  `PATH` inside it: its tools and environment variables;
- **your own profile**, when the distribution turns it on: `~/.nix-profile`
  (`nixProfile.enable`) and your home-manager generation
  (`homeManager.enable`), for the tools and dotfiles you want in every
  project.

### The project's `$HOME`

`~/go/pkg`, `~/.cache`, Claude Code's `~/.claude`, ... persist between runs
and aren't shared with other projects. From your real home it gets only
what's bound in (`binds`) and your own profile.

- **Shell startup.** The sandbox has a managed, read-only `/etc/bashrc` and
  `/etc/profile`, which bash reads before your own files: every interactive
  shell loads bash-completion (also at `/usr/share/bash-completion`), and
  the prompt is `user@project:directory$` where it would be bash's bare
  default - the host name inside is the project's directory name. Your
  `.bashrc`/`.bash_profile` run after them and can override anything.
- **Git identity.** That `$HOME` starts without a `~/.gitconfig`, so unless
  your own profile brings one, the distribution's `git.fromHost` (name,
  email and signing key from your host's global git config) or
  `git.userName`/`git.userEmail` in the project's
  [.sandbox.yml](#per-user-project-settings-sandboxyml) set it.
  `git config --global` inside is saved in that project's `$HOME` only.

### Using devenv

[devenv](https://devenv.sh) runs inside the sandbox like any other tool:
`devenv.nix` and `devenv.yaml` stay as they are, and its shell, scripts,
tasks, processes and services all run sandboxed. devenv itself comes from
the distribution's `packages`, your own profile, or the project
(`sandbox nix run nixpkgs#devenv -- shell` works too, unpinned).

```sh
sandbox devenv shell                     # devenv shell
sandbox devenv up                        # processes and services
sandbox devenv shell -- claude           # Claude Code with devenv's tools on PATH
```

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
| **The distribution's modules**, given to `lib.mkSandbox` | Every [option](#options): packages, `/etc` files, Claude Code, VS Code, guards, binds, `profiles` | Trusted: applies without asking, and wins over the project's settings |
| **The project's [`.sandbox.yml`](#per-user-project-settings-sandboxyml)**, gitignored, each user's own | The guards' token commands and `git.*` | Sandboxed code can edit it: its commands run on the host only once **approved** |
| **The project's dev shell** | Tools and the project's environment variables | Runs inside |

**Approved** means: the commands are shown on the terminal and run only
after your yes. It's asked the first time, and again only for something new
or changed.

### Per-user project settings: .sandbox.yml

What differs per user and project - the token commands' secret-manager
items, the git identity - goes in a `.sandbox.yml` in the project's root,
which the project gitignores (ship a `.sandbox.example.yml` for reference).
Its settings have the configuration's option names, every one is optional,
and an unknown field stops the start:

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

- **Token commands** are approved first: sandboxed code can write this
  file. The distribution's own still win.
- **`git.userName`, `git.userEmail`**: git's author and committer inside.
- **`git.signingKey`**: an ssh public key in your agent; commits and tags
  inside are signed with it (`gpg.format = ssh`), through the ssh agent
  guard, which doesn't ask for those. **`git.signingKeyCommand`** prints
  that key on the host at each start instead, so it's approved.
- **`git.fromHost`**: fill in what isn't set from your global git config on
  the host - `user.name`, `user.email` and, with `gpg.format = ssh`,
  `user.signingKey` (the key, or a key file whose `.pub` is read). Here it
  can also turn the distribution's `git.fromHost` off.

The git settings are git config from the environment, so they override
`~/.gitconfig` inside. `sandbox --no-project-config` ignores the file.

### The distribution's modules

`lib.mkSandbox { pkgs; modules; }` evaluates its modules with the
[options](#options) and `pkgs` given. Split them by concern, so each part is
easy to find and add to - say `claude.nix`, `vscode.nix`, `lsp.nix` - since
options like `packages`, `claude.settings` and `etc` merge across modules:

```nix
# lsp.nix: language servers for Claude Code, and on PATH for VS Code.
{ pkgs, ... }:
{
  claude.lspServers.nil = { package = pkgs.nil; extensionToLanguage.".nix" = "nix"; };
  packages = [ pkgs.nil ];
}
```

The top level applies to every project; [profiles](#profiles) narrow some
settings to projects under given paths.

### Options

[OPTIONS.md](OPTIONS.md) lists every option, with its type, default and
description. It's generated from the declarations in `nix/`, so it says what
the code does. The ones a distribution reaches for first:

- `packages`: tools on `PATH` in every project.
- `etc."<path>"`: read-only files at `/etc/<path>` inside, e.g. config a
  program reads from `/etc`.
- `agentsMd`: added to `/etc/sandbox/AGENTS.md`, for what agents should
  know about the organisation's setup.
- `git.fromHost`, `guards.*`, `binds`, `hostPorts`, `passEnv`.

### Claude Code

`claude.enable` puts `claude` in every project, with managed config at
`/etc/claude-code`, which outranks every settings file in `~/.claude` - the
project's volume, which sandboxed code can write:

```nix
claude = {
  enable = true;
  # managed-settings.json: merged across modules.
  settings.permissions.allow = [ "Bash(go test:*)" ];
  # The managed CLAUDE.md, after the sandbox's AGENTS.md.
  memory = ''
    Run the tests before calling a change done.
  '';
  # managed-mcp.json: once any is set, a project's .mcp.json is ignored.
  # Its tools, like the LSP tool's, are allowed without a prompt, in plan mode too.
  mcpServers.mcp-nixos = { type = "stdio"; command = lib.getExe pkgs.mcp-nixos; };
  # Language servers, each run from its package's bin/, never from PATH.
  lspServers.gopls = { package = pkgs.gopls; extensionToLanguage.".go" = "go"; };
  lspServers.json = {
    package = pkgs.vscode-langservers-extracted;
    executable = "vscode-json-language-server";   # its main program isn't the server
    args = [ "--stdio" ];
    extensionToLanguage.".json" = "json";
  };
  # Plugin directories, pinned in the store like the rest.
  plugins = [ ./claude-plugin ];
};
```

The managed settings get hooks that keep Claude Code from logging gh or fj
in inside, or reaching GitHub around gh, and the auto-updater off (a store
path can't update itself). `claude` is a wrapper that adds the language
servers and plugins (`--plugin-dir`), and the placeholder key when the
sandbox runs the [Claude API guard](#claude-api-key).

Your own `~/.claude` (from home-manager, with `homeManager.enable`) still
applies under the managed config.

### VS Code

`vscode.enable` puts `code` in every project, and turns the
[Wayland guard](#wayland) on for its windows:

```nix
vscode = {
  enable = true;
  extensions = with pkgs.vscode-extensions; [ anthropic.claude-code jnoortheen.nix-ide ];
};
# Copy and paste with the rest of the desktop (see Wayland).
guards.wayland.globals.wl_data_device_manager = true;
```

It runs without Chromium's own sandbox (it needs user namespaces), with
fonts of its own (`vscode.fonts`), and skips the workspace trust prompt
(`vscode.args`): the sandbox is the boundary. Without a Wayland display on
the host it says so and stops. `sandbox code --wait .` keeps the sandbox,
and its guards, up until the window closes.

### Profiles

A profile applies when the sandbox starts under one of its `paths`, never
by what's in a project, which the sandbox writes. Only one applies: the
matching one with the highest `priority` (the first by name on a tie). It
adds `binds` on top of the top level, and can set its own token commands;
everything else is top-level only.

```nix
profiles.audio = {
  paths = [ "~/src/audio" ];
  priority = 20;
  binds = [ { src = "~/Samples"; optional = true; } ];
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

- **Where**: the distribution's config, trusted, where a
  [profile](#profiles) can set them for the projects it matches; or your
  `.sandbox.yml` in a project, approved. The distribution's win.
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

### Claude API key

By default Claude Code is logged in per project, inside the sandbox: start
it (`sandbox claude`), pick the login method, and allow the
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
command and run `claude` inside as usual - no login. The distribution's
[Claude Code](#claude-code) takes the placeholder key the proxy swaps out by
itself; a claude of another kind needs
`apiKeyHelper = "echo sandbox-placeholder"` in its settings. Deleting the key in the
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
one, still applies on top. A login's popup names its server, by the host key
ssh (OpenSSH 8.9 or later) reports and your `known_hosts` on the host; other
clients' logins say the server is unknown.

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
With `guards.wayland.enable` in the distribution's config (`vscode.enable`
turns it on) programs inside open windows on your Wayland display:

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

`guards.notifications.enable = false;` in the distribution's config turns it off.

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
- **A bad `.sandbox.yml` stops the start**: fix it, or start with
  `sandbox --no-project-config`.

## Development

```sh
make test              # everything: nix checks, all tests against a fresh build, and lint
make test RUN=HostPort # only the tests matching a go test -run filter, no lint
make race              # the tests under Go's race detector (minutes)
make coverage          # line coverage of the Go code by the tests
make fmt               # format Go and nix files
make vuln              # known vulnerabilities the Go code reaches
make vendor-hash       # after a go.mod change: the modules' hash in nix/go.nix
make options           # after a change to an option: OPTIONS.md
make demo              # a fresh user in a container, with a distribution of the sandbox installed
```

The demo ([demo/](demo)) runs on the host, in Docker, and its distribution
takes the sandbox from `github:mgnsk/sandbox`, not from the checkout.

The launcher, init and the guards are subcommands of one Go binary,
`sandbox-bin` (`cmd/sandbox-bin`, `internal/`); `sandbox-bin --help` lists
them, and the `sandbox` command is a wrapper around `sandbox-bin launch`
with its configuration, which nix builds from the options
(`nix/module.nix`, `nix/modules/`). Each package has its tests next to it; the launcher's
and init's also run the binary's subcommands, and `e2e/` starts real
sandboxes from a fresh build.

Each target enters the dev shell itself when run outside it. The
real-sandbox tests need unprivileged user namespaces, so they skip inside a
running sandbox: run `make test` on the host for the full suite.
