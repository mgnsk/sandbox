# sandbox

Run coding agents (Claude Code included) and untrusted project builds in a
per-project Linux sandbox: bubblewrap + pasta + seccomp, with every program
inside and outside coming from nix - nothing from the host's `/usr`.

```sh
cd ~/src/some-project
sandbox                         # a login shell in the sandbox (see Install for the command)
sandbox nix develop             # enters the project's dev shell, in the sandbox
sandbox nix develop -c claude   # Claude Code, from the project's dev shell
sandbox nix develop -c make     # or any command
```

The sandbox brings only a shell, nix, git and a few basic tools of its own:
Claude Code and everything else come from the project's dev shell.

What you get, per project:

- **Its own `$HOME`**, kept between runs in `~/.local/share/sandbox`, one
  folder per project.
- **Your project, read-write**: the git work tree you start in (or just the
  current directory outside a repo). Nothing else of your home is visible
  unless you bind it in.
- **No host userland, and few tools of its own.** `PATH` has a fixed
  minimum - bash, nix, git (with `less` and `nano`, its pager and editor)
  and ssh, the coreutils/grep/sed/tar/make set that `nix develop` adds
  anyway, and `jq`, `curl`, `rg`, `which`, `ps`/`pgrep`/`pkill`, `zip` and
  `unzip`. Everything
  else, Claude Code included, comes from the project's dev shell (or, with
  the sandbox installed through home-manager,
  your `~/.nix-profile` and home-manager); no configuration adds tools.
  `/bin/sh`, `/usr/bin/env` and nix-ld for prebuilt binaries are provided.
- **Nix builds** through the host's daemon (`/nix` is read-only inside).
- **Network** out, but not to the host's own services, except the ports you
  open: `hostPorts` in your config, or `SANDBOX_HOST_PORTS="5037 8080/udp"`
  for one run. Ports bound inside are reachable from the host's `127.0.0.1`
  (dev servers, OAuth callbacks).
- **Guarded host access**, credentials kept outside; what could act on your
  behalf waits for a popup on the terminal the sandbox runs in (answer once,
  or "always, for this sandbox"):
  - your ssh agent: logins and pushes ask, commit signing doesn't;
  - the GitHub API, on a token from a token command, from `gh` or any
    other client: writes ask, reads don't;
  - Forgejo APIs (opt-in): the same;
  - windows on your Wayland display (opt-in), through a proxy that passes
    on only what a program needs for its own windows: never asks;
  - the Claude API on an API key from a key command (opt-in): never asks;
  - opening http(s) URLs in the host's browser: asks.
- **A Secret Service** per project, so tools storing credentials via libsecret
  work: their items go to your host keyring, each project's kept apart.
- **An exchange dir** (`$SANDBOX_EXCHANGE`), read-only inside, for output of
  commands you run on the host.
- **Claude Code** with managed settings and a `CLAUDE.md` that tells it about
  all of the above.

See [SECURITY.md](SECURITY.md) for the threat model.

Requirements: Linux with unprivileged user namespaces, nix with a daemon
(multi-user install). Popups need the sandbox started from a terminal (local
or over ssh); without one every guarded request is refused.

On Ubuntu 23.10 and later, AppArmor blocks unprivileged user namespaces for
programs without a profile, which includes bwrap from the nix store. Either
write an AppArmor profile allowing `userns` for that store path, or turn the
restriction off with `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`
(in `/etc/sysctl.d/` to keep it) - which drops that hardening for every
program on the host, not just the sandbox.

## Install

Pick one of two ways to get a `sandbox` command:

- **From this repo, with default settings** - nothing to install:

  ```sh
  cd ~/src/myproject
  nix run github:mgnsk/sandbox -- nix develop -c claude
  ```

  This enters the project's dev shell (`nix develop`) inside the sandbox and
  runs the `claude` it provides: the sandbox ships no Claude Code, so the
  project's flake has `pkgs.claude-code` in its dev shell (see
  [Using it in a project](#using-it-in-a-project)) - or it's in your
  `~/.nix-profile` or home-manager, with the sandbox installed through
  home-manager.

  An alias in your shell config makes it `sandbox`:

  ```sh
  alias sandbox='nix run github:mgnsk/sandbox --'
  ```

  It reads no config of yours; the repo you work on adjusts what applies
  inside through its [sandbox.nix](#the-projects-sandboxnix), and you through
  your [.sandbox.yml](#per-user-project-settings-sandboxyml) there. It can
  be [pinned](#pinning) to a commit.
- **Your home-manager config**, with settings of your own for every
  project: `programs.sandbox`, see [Your sandbox config](#your-sandbox-config).
  The only way to change what applies on the host: `passEnv`, the ssh
  agent socket and guard, profiles, ...

`sandbox` in the rest of this README is whichever of these you use. The repo
you work on brings its own tools through its dev shell (a flake or devenv,
below). For gh, set up [authentication](#authentication) first.

### Pinning

`github:mgnsk/sandbox` follows this repo's default branch, cached for up to
an hour (`tarball-ttl`; `nix run --refresh` fetches it now). To update only
when you choose to, pin a commit you reviewed, and optionally its hash:

```sh
alias sandbox='nix run github:mgnsk/sandbox/<rev> --'
alias sandbox="nix run 'github:mgnsk/sandbox/<rev>?narHash=sha256-...' --"
```

```sh
nix flake metadata --json github:mgnsk/sandbox/<rev> | jq -r .locked.narHash
```

A `github:` ref is fetched as a tarball from GitHub, which nix doesn't check
against the rev; with `narHash` nix refuses anything else ("NAR hash
mismatch"). Keep the alias in your shell config, outside every project.

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

The sandbox brings no tools beyond a shell, nix, git (with `less` and `nano`,
its pager and editor) and ssh, a few basics (`jq`, `curl`, `rg`, `which`,
`ps`, `zip`, `unzip`), and the ones
`nix develop` adds anyway; the dev shell brings the rest, Claude Code and gh
included, and the project's environment variables (`mkShell` attributes,
`shellHook`). Tools you want in every project instead come from your
`~/.nix-profile` or home-manager, with the sandbox installed through
home-manager.

Start the sandbox in the project and enter the dev shell inside it:

```sh
cd ~/src/myproject
sandbox                         # shell in the sandbox
nix develop                     # the project's tools, built through the host's daemon
```

Or in one go:

```sh
sandbox nix develop                    # interactive dev shell
sandbox nix develop -c claude          # Claude Code with the project's tools on PATH
sandbox nix develop -c go test ./...   # a one-off command
```

`command = [ "nix" "develop" ];` in the project's
[sandbox.nix](#the-projects-sandboxnix) makes the dev shell what a bare
`sandbox` runs.

**Shell startup and completion.** The sandbox has a managed, read-only
`/etc/bashrc` and `/etc/profile`, which bash reads before your own files:
every interactive shell loads bash-completion - `nix develop`'s too, finding
the dev shell's completions through the `XDG_DATA_DIRS` it sets. Nothing is
written into your `$HOME`: your `.bashrc`/`.bash_profile` - your own, a bind
(`binds = [ { src = "~/.bashrc"; } ];`) or home-manager's - run after them and
can override anything. bash-completion is also at the fixed path
`/usr/share/bash-completion`.

**Prompt.** The host name inside is the project's directory name, and
`/etc/bashrc` sets the prompt to `user@project:directory$` where it would be
bash's bare default (`bash-5.3$`), so a terminal says which project's sandbox
it is in - `nix develop`'s shell and a VS Code terminal too. A `PS1` of your
own, from your shell files or the dev shell, replaces it.

With direnv, `use flake` in `.envrc` does the same whenever you `cd` in.
`direnv` and `nix-direnv` come from the project's dev shell, or from your
`~/.nix-profile` or home-manager with the sandbox installed through
home-manager.

**The project's `$HOME`** (`~/go/pkg`, `~/.cache`, Claude's `~/.claude`, ...)
persists between runs and isn't shared with other projects. From your real
home it only gets what's linked or bound in: `binds`, and with the sandbox
installed through home-manager your `~/.nix-profile` and
home-manager files.

**Git identity.** That `$HOME` starts without a `~/.gitconfig`, so without
the home-manager module (which links your home-manager git config in) the
first commit fails with "Author identity unknown". Set `git.fromHost` (take
name, email and signing key from your host's global git config) or
`git.userName`/`git.userEmail` in the project's
[.sandbox.yml](#per-user-project-settings-sandboxyml); `sandbox.nix` can set
`git.fromHost` for everyone. Binding `~/.gitconfig` in also works, but
settings in it that point at the host don't: an `include.path` to a file
that isn't bound in, a credential helper that isn't on the sandbox's `PATH`,
`gpg.ssh.program = op-ssh-sign` (see [1Password](#1password)).
`git config --global` inside is saved in that project's `$HOME` only.

### Using devenv

[devenv](https://devenv.sh) runs inside the sandbox like any other tool:
`devenv.nix` and `devenv.yaml` stay as they are, and the sandbox only needs
devenv on `PATH`. Its shell, scripts, tasks, processes and services all run
sandboxed.

devenv itself comes from your side with the sandbox installed through
home-manager, where it is in `~/.nix-profile` or installed
through home-manager, or from the project (see
[devenv from the project's flake](#devenv-from-the-projects-flake) below).

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
sandbox devenv shell -- go test ./...    # a one-off command
```

What to know:

- **Who configures what.** devenv.nix describes the dev environment
  (languages, packages, env, services); sandbox.nix describes the sandbox
  around it (host ports, binds, Claude config). Tools you want in every
  project come from your `~/.nix-profile` or home-manager instead, with the
  sandbox installed through home-manager.
- **Services are inside.** A Postgres or Redis from `services.*` runs in the
  sandbox, so the project reaches it on `127.0.0.1` without `hostPorts`
  (that's for services on the host). Ports bound inside are reachable from
  the host's `127.0.0.1` too, e.g. to open a dev server in your browser.
- **Each sandbox has its own network.** Each `sandbox` run has its own network
  namespace, so services from `devenv up` in one sandbox aren't on
  `127.0.0.1` in another sandbox of the same project. The simplest fix is to
  run everything in one sandbox: `devenv up -d` (detached) and then
  `claude`, or tmux panes inside one `sandbox`. To reach them from a second
  sandbox, go through the host: the first one's ports already show up on the
  host's `127.0.0.1`, so give the second one those ports:

  ```sh
  sandbox devenv up                                               # first: services
  SANDBOX_HOST_PORTS="5432 6379" sandbox devenv shell -- claude   # second
  ```

  Pass them only to the second sandbox, never through `hostPorts` (in
  sandbox.nix or your config). That applies to both sandboxes, and the first one's port
  would then be held for the forward, so its service fails with "address
  in use". Each port can also be taken by only one sandbox (or host
  service) on the host at a time.
- **Containers: build inside, run elsewhere.** `devenv container build` is
  a nix build, so it works; running or loading the image doesn't, as there
  is no Docker daemon inside and rootless podman needs the user namespaces
  the sandbox blocks. Don't give the sandbox `/var/run/docker.sock` or a
  daemon port through `hostPorts`: the Docker API is root on the host.
  Instead, either push to a registry from inside
  (`devenv container copy <name> --registry docker://ghcr.io/you/`, with
  the registry's credentials inside) and pull it where it runs, or write an
  archive into the project (`--registry oci-archive:` writes `./<name>`)
  and `docker load -i <name>` it on the host. Load it with the host's own
  tools - never run scripts from the build output on the host, since the
  sandbox controls what devenv.nix builds.
- **State stays in the project.** `.devenv/` (the eval cache, service data,
  the shell's profile) is in the project directory, and devenv's own caches
  are in the project's `$HOME`, so nothing is shared with devenv on the host
  or other projects.
- **Binary caches.** devenv asks the nix daemon to use the caches in
  `cachix.pull`, which it only does for trusted users. Don't make yourself a
  `trusted-users` entry to get them: a trusted user can make the daemon run
  anything as root, and code in the sandbox talks to the daemon as you.
  Add the caches to the daemon's own config instead (`extra-substituters`
  and `extra-trusted-public-keys` in `/etc/nix/nix.conf`, or `nix.settings`
  on NixOS); devenv's binary caching docs show the keys.
- **Not on the host.** Don't enable devenv's `cd` hook (`devenv allow`) or
  direnv's `use devenv` on the host for a sandboxed project: both evaluate
  and run devenv.nix outside the sandbox, and the sandbox can edit it. Inside
  is fine, if you want activation on `cd` there.

#### devenv from the project's flake

A project can also bring its own devenv, pinned in its `flake.lock`, so it
works without devenv in your profile and everyone gets the same version.
It's built through the host's daemon and runs inside like the rest:

```nix
# flake.nix, next to devenv.nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.devenv.url = "github:cachix/devenv";

  outputs = { nixpkgs, devenv, ... }: {
    packages = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
      (system: { devenv = devenv.packages.${system}.devenv; });
  };
}
```

```nix
# sandbox.nix
{
  command = [ "nix" "run" ".#devenv" "--" "shell" ];
}
```

```sh
sandbox                                      # devenv shell
sandbox nix run .#devenv -- up               # processes and services
sandbox nix run .#devenv -- shell -- claude  # Claude Code with devenv's tools on PATH
```

`sandbox nix run nixpkgs#devenv -- shell` works too, unpinned. devenv's
flake integration (`devenv.lib.mkShell` in `devShells`, entered with
`nix develop --no-pure-eval`) needs no devenv CLI at all, but lacks some of
its commands; see devenv's docs on flakes.

## Configuring the sandbox

### Where settings go

| Where | What it can set | Trust |
| --- | --- | --- |
| **Your sandbox config**: home-manager's `programs.sandbox.settings` | Every [option](#options), including `profiles`; the only place for everything `sandbox.nix` can't set (the ssh agent, open-URL and Secret Service guards, the ssh agent socket, `passEnv`, `stateDir`, ...) | Trusted: applies without asking, and wins over the project's settings |
| **The project's [`sandbox.nix`](#the-projects-sandboxnix)**, committed | `command`, `claude.*`, `hostPorts`, `binds`, the guards' token commands, `guards.wayland`, `git.fromHost`, `git.signingKey`, `git.signingKeyCommand` | Sandboxed code can edit it: binds, host ports and commands run on the host need your yes on the terminal, asked the first time and again only if they change |
| **The project's [`.sandbox.yml`](#per-user-project-settings-sandboxyml)**, gitignored, each user's own | The guards' token commands and `git.*` (identity, signing, `fromHost`) | As `sandbox.nix`; its token commands and git settings override `sandbox.nix`'s |
| **The project's dev shell** (a flake's `devShells`, devenv) | Tools - Claude Code, gh, fj, linters - and the project's environment variables | Runs inside |

`nix run github:mgnsk/sandbox` has no config of yours, only the defaults;
the project's files still apply. Your own tools for every project come from
`~/.nix-profile` or home-manager, with the sandbox installed through
home-manager, not from any of these: `nix run github:mgnsk/sandbox` links
neither.

### The project's sandbox.nix

A `sandbox.nix` in the project root configures the sandbox around the
project, on top of your config - like `devenv.nix`, a module that gets
`pkgs`:

```nix
{ pkgs, ... }:
{
  command = [ "nix" "develop" ];          # what a bare `sandbox` runs
  claude.lspServers.gopls = {
    package = pkgs.gopls;
    extensionToLanguage.".go" = "go";
  };
  claude.settings.permissions.allow = [ "Bash(go test:*)" ];
  hostPorts = [ "5432" ];                 # asked on the terminal the first time, see below
  binds = [ { src = "~/datasets"; } ];    # likewise
}
```

`pkgs` is the sandbox's own nixpkgs. To use the project's pinned one, import
it yourself:

```nix
{ pkgs, ... }:
let
  system = pkgs.stdenv.hostPlatform.system;
  projectPkgs = (builtins.getFlake (toString ./.)).inputs.nixpkgs.legacyPackages.${system};
in
{
  claude.lspServers.gopls = {
    package = projectPkgs.gopls;
    extensionToLanguage.".go" = "go";
  };
}
```

A full example, with every option it can set:

```nix
{ pkgs, lib, ... }:
{
  # What a bare `sandbox` runs, in place of a login shell.
  command = [ "nix" "develop" ];

  # Host ports reachable at 127.0.0.1 inside (port, port/udp or a range).
  # Asked on the terminal the first time.
  hostPorts = [ "5432" "9000-9010" ];

  # Commands printing the API tokens, run on the host at each start.
  # Asked on the terminal the first time. Each user's .sandbox.yml
  # overrides them, and their own sandbox config's win over both.
  guards.github.tokenCommand = "op read op://Employee/GitHub/token";
  guards.forgejo.tokenCommands."codeberg.org" = "op read op://Employee/Codeberg/token";
  guards.claudeApiKey.tokenCommand = "op read op://Employee/Claude/credential";

  # Windows on the user's Wayland display, for GUI programs in the dev
  # shell, and changes to the allowlist of globals (true adds, false
  # removes). Asked on the terminal the first time; see Wayland below.
  guards.wayland.enable = true;
  guards.wayland.globals.wl_data_device_manager = true;   # clipboard, drag-and-drop

  # Git inside: identity and signing key from each user's host git config,
  # and/or a signing key (or a command printing it, asked the first time
  # like the token commands). Each user's .sandbox.yml overrides these too.
  git.fromHost = true;
  git.signingKeyCommand = ''op read "op://Employee/GitHub SSH key/public key"'';

  # Host paths bound in, over whatever the project's $HOME has there.
  # Asked on the terminal the first time.
  binds = [
    { src = "~/datasets"; }                                  # read-only, same path
    { src = "~/src/shared-lib"; hideGit = true; }            # for reference, without its history
    { src = "~/notes/myproject"; dst = "~/notes"; mode = "rw"; optional = true; }
  ];

  claude = {
    # Over your managed settings: objects merge, lists add up, the rest is replaced.
    settings = {
      permissions.allow = [ "Bash(go test:*)" "Bash(golangci-lint run:*)" ];
      permissions.deny = [ "Read(./secrets/**)" ];
      env.GOTOOLCHAIN = "local";
      enabledPlugins."some-plugin@local" = true;
    };

    # Appended to the managed CLAUDE.md.
    memory = ''
      # This project
      Run `go test ./...` and `golangci-lint run` before calling a change done.
    '';

    # Managed MCP servers: once any is set, the project's .mcp.json is ignored.
    mcpServers.mcp-nixos = {
      type = "stdio";
      command = lib.getExe pkgs.mcp-nixos;
    };

    # Each an enabled plugin of a generated `project` marketplace in the store.
    # One with the name of one of yours replaces it.
    lspServers.gopls = {
      package = pkgs.gopls;
      extensionToLanguage.".go" = "go";
      settings.gopls.staticcheck = true;
    };

    # A plugin marketplace in the project (.claude-plugin/marketplace.json);
    # enable its plugins in settings.enabledPlugins (above).
    marketplaces.local = ./claude-plugins;
  };
}
```

How it stays a sandbox, though the sandbox can edit the file:

- **It's evaluated in a sandbox** (a separate one, without the project's
  config), never on the host, which would let it read host files into the
  store. The result is cached until `sandbox.nix`, your sandbox config or the
  profile changes; `sandbox --reload` picks up changes in files it imports,
  and `sandbox --no-project-config` ignores it (and `.sandbox.yml`).
- **The `sandbox` command and everything that runs on the host stay yours**:
  bwrap, pasta, seccomp, the guards and their settings come from your
  sandbox config, never from the project.
- **Binds, host ports and commands run on the host need a yes on the
  terminal**, asked once: the first time, and again only if they change. Everything else only
  affects the inside and applies without asking.

### Per-user project settings: .sandbox.yml

`sandbox.nix` is the project's, committed. What differs per user - the
token commands' secret-manager items, the git identity - goes in a
`.sandbox.yml` next to it, which the project gitignores (ship a
`.sandbox.example.yml` for reference). Its settings have `sandbox.nix`'s
option names, and every one is optional:

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

```gitignore
.sandbox.yml
```

A field it doesn't know (a typo) stops the start.

- **Token commands** go over `sandbox.nix`'s. They're still the project's
  to the sandbox - sandboxed code can write this file like any other in
  the project - so they're shown and approved like `sandbox.nix`'s, the
  first time and again only if they change. Your own config's still win.
- **`git.userName`, `git.userEmail`**: git's author and committer inside.
  Only here: they're each user's.
- **`git.signingKey`**: an ssh public key in your agent; commits and tags
  inside are signed with it (`gpg.format = ssh`), through the ssh agent
  guard, which doesn't ask for signatures. **`git.signingKeyCommand`**,
  instead, prints that public key on the host at each start, so it's
  approved the first time, like the token commands. Set one; either replaces both of
  `sandbox.nix`'s.
- **`git.fromHost`**: fill in what isn't set from your global git config on
  the host - `git config --global` for `user.name`, `user.email` and, with
  `gpg.format = ssh`, `user.signingKey` (the key, or a key file whose `.pub`
  is read). Only that runs, from `/`, never in the project. Here it can
  also turn `sandbox.nix`'s `git.fromHost` off.

The git settings only affect the inside, so they apply without asking
(but a signing key command, which runs on the host, is approved the first
time). They're
git config from the environment, so they override `~/.gitconfig` inside.

### Your sandbox config

Your own sandbox config is a list of modules with the [options](#options)
below. Its top level applies to every project; `profiles` narrow some
settings to projects under given paths (see [Profiles](#profiles)). It
comes from your home-manager config, never from a project:
`programs.sandbox.settings` takes the module, with your home-manager `pkgs`:

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

Only the sandbox installed this way brings your own environment in. It
links your current home-manager generation into each project's `$HOME` at
every start (`homeManager.enable`), so your shell config, git config, etc.
apply inside, and your `~/.nix-profile` (`nixProfile.enable`), with its
`bin/` on `PATH`.

The sandbox a project starts with `nix run github:mgnsk/sandbox` links
neither, so that everyone gets the same environment there: the project's dev
shell. A project has one `$HOME` whichever sandbox starts it, so such a
start also removes the links your own `sandbox` made in it; your next start
with that links them again.

### Options

The options of your sandbox config; all are in [nix/module.nix](nix/module.nix).
`binds`, `hostPorts`, `claude.*` (except `enable`), the token commands and
`guards.wayland` can also be set by a project's `sandbox.nix`.

| Option | Default | |
| --- | --- | --- |
| `passEnv` | `[ ]` | Host variables passed in, besides TERM/COLORTERM/LANG/LC_ALL; everything else is cleared. |
| `binds` | `[ ]` | Host paths bound in: `{ src; dst; mode = "ro" \| "rw"; optional; hideGit; }`; `~`, `$HOME`, `$USER`, `$XDG_RUNTIME_DIR` expanded in `src`. One whose src is the project is left to the project bind. |
| `hostPorts` | `[ ]` | Like `SANDBOX_HOST_PORTS`, always. |
| `stateDir` | `$XDG_DATA_HOME/sandbox` | One folder per project: its `$HOME`, exchange dir, `sandbox.nix` approvals and cache. `$SANDBOX_STATE_DIR` overrides. |
| `nixLd.libraries` | libstdc++, zlib, openssl, curl, libgcc | For prebuilt binaries. |
| `nixConfig` | flakes on | `NIX_CONFIG` inside; there is no nix.conf in there. |
| `nixProfile.enable` | off (on with the home-manager module) | Link the host's `~/.nix-profile` in and put its `bin/` on `PATH`, after the sandbox's own. Off, a link from an earlier start is removed. |
| `homeManager.enable` | off (on with the home-manager module) | Link your current home-manager generation into each project's `$HOME` at every start. Off, the links of an earlier start are removed. |
| `locales` | C.UTF-8, en_US.UTF-8 | glibcLocales build for `LOCALE_ARCHIVE`; override to add yours. |
| `guards.sshAgent` | on, `$SSH_AUTH_SOCK` | `enable`, `socket` (host) and `path` (inside). See [SSH agent](#ssh-agent). |
| `guards.github.tokenCommand` | none | A shell command printing the token, run on the host at each start (see [Authentication](#authentication)); the host's gh is never used. |
| `guards.forgejo.tokenCommands.<host>` | `{ }` | The same per Forgejo host; the host's fj is never used. |
| `guards.claudeApiKey.tokenCommand` | none | A shell command printing a Claude API key, run on the host at each start: Claude Code then runs on it, held outside. See [Claude Code](#claude-code). |
| `guards.openUrl.enable` | on | `xdg-open` inside opens http(s) URLs in the host's browser, after a popup. |
| `guards.secretService.enable` | on | A per-project Secret Service on a private D-Bus, for tools using libsecret, storing in the host's Secret Service (gnome-keyring, KeePassXC, ...). Needs one running, or D-Bus-activatable, on the host's session bus: without it the sandbox doesn't start - turn this off then. |
| `guards.notifications.enable` | on | With a Wayland display inside, show a popup as a desktop notification too when the request doesn't come from the sandbox's terminal. See [Popups from a window](#popups-from-a-window). |
| `guards.wayland.enable` | `null` | Windows on your Wayland display, through a filtering proxy: `true` or `false` for every project, `null` to leave it to each project's `sandbox.nix`. See [Wayland](#wayland). |
| `guards.wayland.globals.<name>` | `{ }` | Changes to the allowlist of Wayland globals: `true` adds one, `false` removes one. Yours go over a project's. |
| `claude.enable` | on | Claude Code's managed config (settings, memory, MCP and language servers) at `/etc/claude-code`, for the `claude` your dev shell or profile brings: the sandbox ships none. |
| `claude.settings` | autoupdater off, hooks steering GitHub HTTP requests to `gh` and denying `gh`/`fj` logins | managed-settings.json, merged across modules. |
| `claude.memory` | sandbox, GitHub, Forgejo notes | Managed CLAUDE.md; your lines are appended. |
| `claude.mcpServers` | `{ }` | Managed MCP servers (exclusive: a project's .mcp.json is then ignored). |
| `claude.lspServers.<name>` | `{ }` | `{ package; executable; args; extensionToLanguage; settings; }`: language servers as enabled plugins of a generated `sandbox` marketplace in the store. The server is always `package`'s `bin/<executable>` (default: its `meta.mainProgram`), never a command on `PATH`. |
| `claude.marketplaces.<name>` | `{ }` | Plugin marketplace directories (store paths); enable their plugins in `claude.settings.enabledPlugins`. |
| `profiles.<name>` | `{ }` | Per-project additions, see [Profiles](#profiles). |

### Plugins and language servers

Plugins come from marketplaces in the store, pinned like everything else,
not from git checkouts that update themselves in each project's `$HOME`.
In your sandbox config, a profile or a project's `sandbox.nix`:

```nix
claude.lspServers = {
  gopls = { package = pkgs.gopls; extensionToLanguage.".go" = "go"; };
  ty = {
    package = pkgs.ty;
    args = [ "server" ];
    extensionToLanguage = { ".py" = "python"; ".pyi" = "python"; };
  };
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

Once any marketplace or language server is set, these are the only
marketplaces Claude Code knows: they're registered in each project's `$HOME`
before its first session (so enabled plugins work from the start), and the
official marketplace and `/plugin marketplace add` are refused.

### Profiles

Profiles are only in your sandbox config, never in `sandbox.nix`. A profile
applies when the sandbox starts under one of its `paths`, or in a project
whose root has one of its `projectFiles`. Only one applies: the matching one
with the highest `priority` (the first by name on a tie), so profiles don't
combine with each other. It adds `binds` and `claude.*` (language servers
and marketplaces included) on top of the top level, and can set its own
token commands (`guards.github.tokenCommand`, `guards.forgejo.tokenCommands`,
`guards.claudeApiKey.tokenCommand`). Everything else is top-level only.

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
    claude.mcpServers.reaper = { type = "stdio"; command = "/path/to/reaper-mcp"; };
  };
};
```

## Authentication

### GitHub and Forgejo

> [!WARNING]
> ## Never run `gh auth login` or `fj auth login` inside the sandbox
>
> **A token stored inside the sandbox is readable by everything that runs
> there, and requests made with it skip the host proxy and its write
> popups.** Tokens come only from a token command, which runs on the host
> (see below). If you already logged in inside, run `gh auth logout` /
> `fj auth logout` there and revoke that token.
>
> The sandbox blocks the usual ways in - gh refuses to log in while the
> guard's `GH_TOKEN` is set, forgejo-api-proxy refuses fj's OAuth login,
> and a Claude Code hook denies the login commands - and warns at each
> start of any login it finds stored inside. A token pasted in by hand
> still can't be stopped.

**gh and fj** talk to their APIs through host proxies that add a token to
each request (writes behind a popup). The token never enters the sandbox and
is never written to disk: a **token command** prints it on the host at each
start - typically your secret manager - and it's handed to the proxy in
memory. gh or fj on the host, and any login they have, are never used.

The project can declare its commands in its `sandbox.nix`, so everyone
working on it is set up by starting the sandbox (or each user in their own
[.sandbox.yml](#per-user-project-settings-sandboxyml), when the commands
differ per user):

```nix
guards.github.tokenCommand = "op read op://Employee/GitHub/token";
guards.forgejo.tokenCommands."codeberg.org" = "op read op://Employee/Codeberg/token";
```

These run on your host, as you, so the sandbox shows them on the terminal
and runs them only once you say yes - asked the first time, and again only
if they change (sandboxed code can edit `sandbox.nix`). The same options in your own
sandbox config are trusted: they run without asking, and win over the
project's. There, a [profile](#profiles) can set them for the projects it
matches. The GitHub and Forgejo guards have no switch: each runs once it
has a token command.

The command runs from `/`, with your terminal, so `op` can ask you to unlock
it, and your `PATH`. If it fails or prints no token, the sandbox doesn't
start. Without a command the guard doesn't run: requests to GitHub's API,
or to a Forgejo host without one, go out without a token. A new token takes a restart.

For GitHub, use a
[fine-grained token](https://github.com/settings/personal-access-tokens/new)
limited to the project's repositories, with what gh needs there: typically
read-only Contents and Actions, read-write Issues and Pull requests. Pushes
go over ssh, so the token needn't write Contents.

Any command that prints the token works, not only a secret manager's. If
you're logged in with gh on the host, it can hand over that login's token:

```nix
guards.github.tokenCommand = "gh auth token";
```

That's gh on your host, run at each start like any token command; the
sandbox doesn't otherwise touch it. Its token is your whole GitHub login,
though - every repository and organization you can reach - so a
fine-grained token limited to the project bounds what a misbehaving
sandbox can do better. Put it in your own sandbox config or `.sandbox.yml`
rather than a project's `sandbox.nix`, since it depends on your host's gh.

**How gh and fj reach the proxies.** The sandbox ships neither: bring them
like any other tool, in the project's dev shell, `~/.nix-profile` or
home-manager. Whichever one runs reaches the guards the same way. With a
GitHub or Forgejo token command set, every process inside gets `HTTPS_PROXY`
pointing at a small router on the sandbox's own loopback, started before
your command. It sends `CONNECT`s for the GitHub API hosts to gh-api-proxy,
for Forgejo instances with a token to forgejo-api-proxy, and everything else
straight out over the sandbox's network, as without a proxy.
`SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and
`REQUESTS_CA_BUNDLE` add the guards' CAs, so clients complete TLS with them
(code calling a pip-installed `certifi.where()` itself still won't);
`NO_PROXY` keeps loopback direct, for dev servers. Clients that ignore
`HTTPS_PROXY` simply bypass it (and reach the APIs without a token). A host
`HTTPS_PROXY` passed in with `passEnv` is replaced: the router dials out
directly.

### Claude Code

By default Claude Code is logged in per project, inside the sandbox, since
its credentials live in the project's `~/.claude`. Code running in that
sandbox can read them (see [SECURITY.md](SECURITY.md)); with an API key, the
guard below keeps the key outside instead.

1. Start it in the project: `sandbox nix develop -c claude` (the dev shell's
   Claude Code; plain `sandbox claude` works only with one in your
   `~/.nix-profile` or home-manager).
2. Pick the login method; Claude Code shows a login URL and tries to open it.
   Allow the popup to open it in the host's browser, or copy the link and open
   it yourself.
3. Confirm in the browser (paste the code back into Claude Code if it asks).

Every new project needs this once; the login then persists in that project's
volume. Other projects, and Claude Code on the host, keep their own logins.

**On an API key**: with a key command, the key stays on the host, and a
proxy adds it to Claude Code's requests. It works like the GitHub token
command: printed at each start, held in memory, from your sandbox config
(trusted) or the project's `sandbox.nix` or `.sandbox.yml` (approved the
first time):

```nix
guards.claudeApiKey.tokenCommand = "op read op://Employee/Claude/credential";
```

1. Create a key for the project at
   [platform.claude.com](https://platform.claude.com/settings/keys), ideally
   in a workspace with a spend limit, and store it in your secret manager.
2. Set the command; start the sandbox (approving it the first time, if it's the
   project's).
3. Run `claude` inside as usual - no login.

Deleting the key in the Console cuts off just that project. A subscription
login can't go through the proxy: Anthropic doesn't allow tools to hold
claude.ai credentials. If the project was logged in inside before, run
`/logout` there so that login doesn't stay in the volume.

Without a key command Claude Code logs in inside, per project. A profile in
your sandbox config can set its own command, so some projects use a key
while others log in with a subscription; with home-manager:

```nix
programs.sandbox.settings.profiles.work = {
  paths = [ "~/work" ];
  guards.claudeApiKey.tokenCommand = "op read op://Employee/Claude/credential";
};
```

### Wayland

Off by default: without it there is no display inside, and no GUI programs.
With `guards.wayland.enable`, programs inside open windows on your Wayland
display:

```nix
# sandbox.nix, for everyone working on the project (approved on the
# terminal the first time), or your own sandbox config (trusted)
guards.wayland.enable = true;
```

Inside, `WAYLAND_DISPLAY` is `wayland-0`, a socket of the sandbox's own. Your
compositor's real socket is never bound in: on it, any client gets whatever
the compositor offers, which on wlroots compositors (sway, ...) includes the
screen's contents, the clipboard at any time and synthetic keyboard and
pointer input. The guard is a proxy on the host,
[wl-veil](https://github.com/mahkoh/wl-proxy), which passes on only an
allowlist of the compositor's globals - by default what a program needs to
show and drive its own windows ([nix/wayland.nix](nix/wayland.nix)) - and
only binds of those. It works the same on every compositor, and never asks.

**The clipboard is off by default.** `wl_data_device_manager` (the clipboard
and drag-and-drop) and `zwp_primary_selection_device_manager_v1` (the primary
selection) let a window read what you last copied on the host whenever it
has the keyboard focus, so they're not on the list: copy and paste between
the host and a program inside doesn't work, and some programs (foot) don't
start. Add them where you want that:

```nix
guards.wayland.globals = {
  wl_data_device_manager = true;                   # add to the allowlist
  zwp_primary_selection_device_manager_v1 = true;
  zwp_pointer_constraints_v1 = false;              # or take one off it
};
```

The allowlist is the defaults, then the project's `sandbox.nix`'s changes,
then your own config's: yours win. A global a project adds needs your yes
like turning the guard on does; one it removes doesn't. A name wl-veil
doesn't know is reported at start and ignored.

#### Popups from a window

The guards' popups are drawn on the terminal the sandbox runs on, which you
aren't looking at while you work in a window: a push from an editor inside
would just seem to hang. So in a sandbox with a Wayland display, a request
is shown as a desktop notification as well, with the same three answers -
Allow once, Always in this sandbox, Deny - unless it comes from a program on
the sandbox's own terminal (a `git push` typed there asks there alone, as
ever).

- The popup on the terminal stays: whichever is answered first counts, and
  the other goes away. Closing the notification without picking an answer is
  a no.
- It's sent on your session bus, by the launcher. Nothing inside reaches that
  bus, so a notification can't be answered or forged from the sandbox.
- A long request (a long URL, say) is cut in the notification, which says
  so: it shows the start - the host of a URL, the command, the method and
  path of an API request come first - and the whole of it is on the
  terminal. Answering from the notification approves the request as it is,
  not only what the notification shows.
- It needs a notification daemon that advertises actions (tried with
  swaync); without one the launcher says so at start and asks on the
  terminal only. It's sent as critical and never expiring, which
  keeps it on screen in the common daemons; one that takes it away anyway
  gets it again, and the terminal still asks.
- Requests through the GitHub and Forgejo API guards can't be traced to the
  program that made them, so they're always shown both ways.

`guards.notifications.enable = false;` in your sandbox config turns it off.

What the sandbox doesn't have, with or without the guard: a GPU (`/dev/dri`
isn't there, so programs render in software), X11, and fonts or a fontconfig
of the host's - the dev shell brings those. Chromium and Electron programs
need `--no-sandbox` (their own sandbox wants user namespaces) and
`--ozone-platform=wayland`.

### SSH agent

The ssh agent guard proxies whichever agent `$SSH_AUTH_SOCK` points to when
the sandbox starts (`guards.sshAgent.socket` in your sandbox config to pick
another, e.g. if you start `sandbox` from somewhere it isn't set). Inside,
only the guard's proxy is visible, never the real socket. A sign request (an
ssh login, `git push` over ssh) gets the sandbox's popup first, except git
commit and tag signatures; the agent's own approval, if it has one, still
applies on top.

If your shell config sets `SSH_AUTH_SOCK` unconditionally (e.g. home-manager
session variables, which the shell inside sources too with
`homeManager.enable`), it overrides the guard's proxy.
Either keep a value that's already set, in your home-manager config:

```nix
home.sessionVariables.SSH_AUTH_SOCK = "\${SSH_AUTH_SOCK:-$HOME/.1password/agent.sock}";
```

or put the proxy where your config points, in your sandbox config:

```nix
guards.sshAgent.path = "~/.1password/agent.sock";
```

Your `~/.ssh/config` isn't there inside, only your `known_hosts` (read-only,
as the system-wide one). Without home-manager's `programs.ssh`, bind it in
with `binds = [ { src = "~/.ssh/config"; } ];`. Keys stay in the agent;
`IdentityFile` lines naming private keys find nothing inside, but a public
key there still picks the agent key to use, if you bind that `.pub` file in
too.

**Commit signing:** `git.signingKey`, `git.signingKeyCommand` or
`git.fromHost` (in [.sandbox.yml](#per-user-project-settings-sandboxyml) or
`sandbox.nix`) set it up. In a git config of your own, use
`gpg.format = ssh` with `user.signingKey` set to the public key itself
(`ssh-ed25519 AAAA...`), so `ssh-keygen` signs through the agent.

#### 1Password

Its agent is `~/.1password/agent.sock` (Settings → Developer → Use the SSH
agent); with `SSH_AUTH_SOCK` set to that on the host, the defaults work.
`gpg.ssh.program = op-ssh-sign` doesn't work inside: it talks to the app
directly rather than through the agent socket, and the app isn't reachable
inside.

**`op` (the 1Password CLI)** can't use the desktop app integration inside. The
app only accepts `op` running setgid as the `onepassword-cli` group, and
setuid/setgid does nothing in the sandbox (`no_new_privs`), so binding the
app's sockets in wouldn't help either. A manual `op account add` or a service
account token (`OP_SERVICE_ACCOUNT_TOKEN`) would work, but that puts a
1Password credential inside the sandbox, where the project's code can read it.
Use `op` on the host instead.

## Development

```sh
make test              # everything: all tests against a fresh build, and lint
make test RUN=HostPort # only the tests matching a go test -run filter, no lint
make coverage          # line coverage of the Go code by the tests
make fmt               # format Go and nix files
make demo-flake        # a fresh user in a container: a project with flake.nix and sandbox.nix
make demo-home-manager # the same with the sandbox from a home-manager config
```

The demos ([demo/](demo)) run on the host, in Docker, and take the sandbox
from `github:mgnsk/sandbox` like `nix run` does, not from the checkout.

The launcher, init and the guards are subcommands of one Go binary,
`sandbox-bin` (`cmd/sandbox-bin`, `internal/`); `sandbox-bin --help` lists
them, and the `sandbox` command is a wrapper around `sandbox-bin launch`
with its configuration. Each package has its tests next to it; the
launcher's and init's also run the binary's subcommands, and `e2e/` starts
real sandboxes from a fresh build.

Each target enters the dev shell itself when run outside it. The real-sandbox
tests need unprivileged user namespaces, so they skip inside a running
sandbox: run `make test` on the host for the full suite.
