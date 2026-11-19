# sandbox

Run coding agents (Claude Code included) and untrusted project builds in a
per-project Linux sandbox: bubblewrap + pasta + seccomp, with every program
inside and outside coming from nix - nothing from the host's `/usr`.

```sh
cd ~/src/some-project
sandbox          # a login shell in the sandbox
sandbox claude   # or any command
```

What you get, per project:

- **Its own `$HOME`**, kept between runs in `~/.local/share/sandbox`, one
  folder per project.
- **Your project, read-write**: the git work tree you start in (or just the
  current directory outside a repo). Nothing else of your home is visible
  unless you bind it in.
- **No host userland.** `PATH` is a nix package set (bash, coreutils, git,
  openssh, curl, python3, nix, claude, ...), plus `~/.nix-profile/bin`.
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
  - the GitHub API (the host's or the project's token), from `gh` or any
    other client: writes ask, reads don't;
  - Forgejo APIs (opt-in): the same;
  - the Claude API on a per-project API key (opt-in): never asks;
  - opening http(s) URLs in the host's browser: asks.
- **A Secret Service** per project, so tools storing credentials via libsecret
  work without a desktop keyring.
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

There's no `sandbox` package to install on its own: it's built from a
configuration, in one of two places.

- **Your home-manager config**, for every project you work on:
  `programs.sandbox`, see [With home-manager](#with-home-manager).
- **A project's flake**, for everyone working on that project: run from the
  project's remote, never from a checkout, see
  [In a project's flake](#in-a-projects-flake).

Either way a project brings its own tools through its dev shell (a flake or
devenv, below). For gh, set up [authentication](#authentication) first.

## Using it in a project

Say a project has just a `flake.nix` with a dev shell:

```nix
{
  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs = { nixpkgs, ... }:
    let pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in {
      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [ pkgs.go pkgs.gopls pkgs.golangci-lint ];
      };
    };
}
```

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

With direnv, `use flake` in `.envrc` does the same whenever you `cd` in. Put
`direnv` and `nix-direnv` in `packages` in
[your sandbox config](#configuring-the-sandbox), or in `~/.nix-profile`.

The project's `$HOME` (`~/go/pkg`, `~/.cache`, Claude's `~/.claude`, ...)
persists between runs and isn't shared with other projects. From your real
home it only gets what's linked or bound in: `~/.nix-profile`, your
home-manager files (with the home-manager module) and your `binds`.

### Authentication

**gh and fj** talk to their APIs through host proxies that add a token to
each request (writes behind a popup); the token itself never enters the
sandbox. It comes from either place, the project's own winning:

- **Per project**, no gh or fj needed on the host. Run in the project, in a
  terminal on the host - not inside the sandbox, which includes Claude Code's
  `!` commands:

  ```sh
  sandbox --gh-token                 # asks for a GitHub token
  sandbox --fj-token codeberg.org    # asks for a token for that Forgejo instance
  ```

  The token is read on the terminal (hidden input) and kept in the project's
  folder under `~/.local/share/sandbox`, next to its `$HOME` but outside the
  sandbox; running sandboxes pick it up. For GitHub,
  use a [fine-grained token](https://github.com/settings/personal-access-tokens/new)
  limited to the project's repositories, with what gh needs there: typically
  read-only Contents and Actions, read-write Issues and Pull requests. Pushes go
  over ssh, so the token needn't write Contents. Run it again to replace the
  token. To remove it, delete `github-token` (or the host's entry in
  `forgejo-tokens.json`) from the project's folder under
  `~/.local/share/sandbox` - the folder named after the project's path.

- **The host's login**, shared by every project without a token of its own:

  ```sh
  gh auth login                            # on the host
  fj --host codeberg.org auth login        # on the host, if you enabled guards.forgejo
  ```

  The gh proxy reads the host's token when the sandbox starts, so after
  logging in again on the host (or switching accounts) restart the sandbox;
  fj's proxy reads it per request.

Don't run `gh auth login` or `fj auth login` inside: a token stored inside
would bypass the proxy and its popups. A request without any token is refused
with a message saying which command to run.

**Claude Code** is logged in per project, inside the sandbox, since its
credentials live in the project's `~/.claude`. Code running in that sandbox
can read them (see [SECURITY.md](SECURITY.md)); with an API key, the guard
below keeps the key outside instead.

1. Start it in the project: `sandbox claude`.
2. Pick the login method; Claude Code shows a login URL and tries to open it.
   Allow the popup to open it in the host's browser, or copy the link and open
   it yourself.
3. Confirm in the browser (paste the code back into Claude Code if it asks).

Every new project needs this once; the login then persists in that project's
volume. Other projects, and Claude Code on the host, keep their own logins.

**Claude Code on an API key** (`guards.claudeApiKey.enable = true`): the key
stays on the host, and a proxy adds it to Claude Code's requests.

1. Create a key for the project at
   [platform.claude.com](https://platform.claude.com/settings/keys), ideally
   in a workspace with a spend limit.
2. Start the sandbox in the project; at the first start it asks for the key
   on the terminal (hidden input) and keeps it in the same project folder as
   the gh and fj tokens, outside the sandbox.
3. Run `claude` inside as usual - no login.

`sandbox --claude-api-key` replaces the key (running sandboxes pick it up);
deleting it in the Console cuts off just that project. A subscription login
can't go through the proxy: Anthropic doesn't allow tools to hold claude.ai
credentials. If the project was logged in inside before, run `/logout` there
so that login doesn't stay in the volume.

The option is per profile, so some projects can use a key while others log in
with a subscription:

```nix
guards.claudeApiKey.enable = true;                  # API keys by default
profiles.personal = {
  paths = [ "~/personal" ];
  guards.claudeApiKey.enable = false;               # subscription login here
};
```

or the other way round, `true` only in the profiles that should use a key.

### SSH agent

The ssh agent guard proxies whichever agent `$SSH_AUTH_SOCK` points to when
the sandbox starts (`guards.sshAgent.socket` to pick another, e.g. if you
start `sandbox` from somewhere it isn't set). Inside, only the guard's proxy
is visible, never the real socket. A sign request (an ssh login, `git push`
over ssh) gets the sandbox's popup first, except git commit and tag
signatures; the agent's own approval, if it has one, still applies on top.

If your shell config sets `SSH_AUTH_SOCK` unconditionally (e.g. home-manager
session variables, which the shell inside sources too with
`homeManager.enable`), it overrides the guard's proxy.
Either keep a value that's already set:

```nix
home.sessionVariables.SSH_AUTH_SOCK = "\${SSH_AUTH_SOCK:-$HOME/.1password/agent.sock}";
```

or put the proxy where your config points:

```nix
guards.sshAgent.path = "~/.1password/agent.sock";
```

Your `~/.ssh/config` isn't there inside, only your `known_hosts` (read-only,
as the system-wide one). Without home-manager's `programs.ssh`, bind it in
with `binds = [ { src = "~/.ssh/config"; } ];`. Keys stay in the agent;
`IdentityFile` lines naming private keys find nothing inside, but a public
key there still picks the agent key to use, if you bind that `.pub` file in
too.

**Commit signing:** use `gpg.format = ssh` with `user.signingKey` set to the
public key itself (`ssh-ed25519 AAAA...`), so `ssh-keygen` signs through the
agent.

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

### Git config without home-manager

Each project's `$HOME` starts empty, so without the home-manager module git
inside has no `~/.gitconfig`, and the first commit fails with "Author
identity unknown". Pick one of these in [your sandbox config](#configuring-the-sandbox),
at the top level (`env` isn't taken by a project's `sandbox.nix` or a profile).

Bind your host config in, read-only, for every project:

```nix
binds = [
  { src = "~/.gitconfig"; }
  { src = "~/.config/git"; optional = true; }
];
```

Settings in it that point at the host don't work inside: an `include.path`
to a file that isn't bound in, a credential helper that isn't on the
sandbox's `PATH`, and `gpg.ssh.program = op-ssh-sign` (see
[1Password](#1password)).

Or set only what's needed, with no host file:

```nix
env = {
  GIT_AUTHOR_NAME = "Your Name";
  GIT_AUTHOR_EMAIL = "you@example.com";
  GIT_COMMITTER_NAME = "Your Name";
  GIT_COMMITTER_EMAIL = "you@example.com";
  # Any other setting, numbered from 0:
  GIT_CONFIG_COUNT = "1";
  GIT_CONFIG_KEY_0 = "pull.rebase";
  GIT_CONFIG_VALUE_0 = "true";
};
```

For signed commits, add `gpg.format = ssh`, `user.signingKey` and
`commit.gpgSign = true` the same way; see [SSH agent](#ssh-agent).

`git config --global` inside also works, but it's saved in that project's
`$HOME`, so every project needs it once.

### The project's own sandbox config: sandbox.nix

A `sandbox.nix` in the project root configures the sandbox around the
project, on top of yours - like `devenv.nix`, a module that gets `pkgs`:

```nix
{ pkgs, ... }:
{
  command = [ "nix" "develop" ];          # what a bare `sandbox` runs
  claude.lspServers.gopls = {
    package = pkgs.gopls;
    extensionToLanguage.".go" = "go";
  };
  claude.settings.permissions.allow = [ "Bash(go test:*)" ];
  hostPorts = [ "5432" ];                 # needs your approval, see below
  binds = [ { src = "~/datasets"; } ];    # likewise
}
```

It can set `command`, `claude.*` (settings, memory, MCP and language
servers, marketplaces), `hostPorts` and `binds` - not `packages` or `env`.
The project's tools and variables belong in its dev shell (a flake's
`devShells`, devenv), which `command` enters, so they're defined once; your
own tools come from your sandbox config, `~/.nix-profile` or home-manager.

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
  # Needs your approval on the terminal.
  hostPorts = [ "5432" "9000-9010" ];

  # Host paths bound in, over whatever the project's $HOME has there.
  # Needs your approval on the terminal.
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
  and `sandbox --no-project-config` ignores it.
- **The `sandbox` command and everything that runs on the host stay yours**:
  bwrap, pasta, seccomp, the guards and their settings come from your
  installed configuration, never from the project.
- **Binds and host ports need a yes on the terminal**, the first time and
  whenever they change. Everything else only affects the inside and applies
  without asking.

A language server it defines replaces one of yours with the same name.

If the sandbox itself is defined in the project's flake, run it from the
project's remote, never from the checkout (`nix run .#sandbox`): the sandbox
can edit `flake.nix`, and that `nix run` would run whatever it put there on
the host. See [In a project's flake](#in-a-projects-flake).

### Using devenv

[devenv](https://devenv.sh) runs inside the sandbox like any other tool:
`devenv.nix` and `devenv.yaml` stay as they are, and the sandbox only needs
devenv on `PATH`. Its shell, scripts, tasks, processes and services all run
sandboxed.

devenv itself comes from your side: `packages = [ pkgs.devenv ]` in your
sandbox config, or installed in `~/.nix-profile` or through home-manager.

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
  project go in your own config instead.
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

## Configuring the sandbox

A sandbox configuration is a list of modules with the options in
[Configuration](#configuration). Its top level applies to every project;
`profiles` narrow some settings to projects under given paths (see
[Profiles](#profiles)). It comes from your home-manager config or from a
project's flake run from its remote - never from a checkout a sandbox can
write.

### With home-manager

`programs.sandbox.settings` takes the module, with your home-manager `pkgs`:

```nix
modules = [
  inputs.sandbox.homeManagerModules.default
  {
    # Your home-manager pkgs must allow the unfree claude-code
    # (or set programs.sandbox.settings.claude.package = null to use your own).
    programs.sandbox.enable = true;
    programs.sandbox.settings = {
      packages = [ pkgs.neovim ];
      env.EDITOR = "nvim";
      guards.forgejo.enable = true;
      profiles.work = {
        paths = [ "~/work" ];
        guards.claudeApiKey.enable = true;
      };
    };
  }
];
```

Updating is updating the flake input your home-manager config takes it from,
then switching.

The home-manager module also links your current home-manager generation into
each project's `$HOME` at every start (`homeManager.enable`), so your shell
config, git config, etc. apply inside. Without it, see
[Git config without home-manager](#git-config-without-home-manager) and
[SSH agent](#ssh-agent) for binding your config in.

### In a project's flake

A project can ship the sandbox to everyone working on it: its flake builds
one with `mkSandbox`, and each user runs it from the project's remote, either
following its default branch or pinned to a commit:

```nix
{
  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.sandbox.url = "github:mgnsk/sandbox";
  inputs.sandbox.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { nixpkgs, sandbox, ... }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        # claude-code is unfree
        config.allowUnfreePredicate = p: nixpkgs.lib.getName p == "claude-code";
      };
    in {
      packages.x86_64-linux.sandbox = sandbox.lib.mkSandbox {
        inherit pkgs;
        modules = [ { guards.forgejo.enable = true; } ];
      };
      devShells.x86_64-linux.default = pkgs.mkShell { packages = [ /* ... */ ]; };
    };
}
```

```sh
cd ~/src/myproject

# The default branch: updates arrive with merges.
nix run github:owner/myproject#sandbox -- nix develop -c claude

# A commit you reviewed: updates only when you change the rev.
nix run github:owner/myproject/<rev>#sandbox -- nix develop -c claude

# The same, also checking what GitHub serves against a hash you recorded.
nix run 'github:owner/myproject/<rev>?narHash=sha256-...#sandbox' -- nix develop -c claude
```

The `narHash` of a commit, to pin it with:

```sh
nix flake metadata --json github:owner/myproject/<rev> | jq -r .locked.narHash
```

A `github:` ref is fetched as a tarball from GitHub, which nix doesn't check
against the rev; with `narHash` nix refuses anything else ("NAR hash
mismatch"). Keep the pinned ref in your shell config (e.g. an alias), outside
every project.

What makes this safe is where it runs from, so:

- **Always the remote, never a checkout.** Not `nix run .#sandbox`, not
  `nix run ~/src/myproject#sandbox`: a sandbox can write its project, `.git`
  included, so a checkout holds whatever sandboxed code put there, and the
  launcher runs on the host. A short alias for the remote URL helps.
- **Review what runs.** Following the default branch, that's everything
  merged into it: protect the branch, so changes need review like any code
  that runs unsandboxed. Pinned, it's the commit you pin; read the diff
  before moving the pin. Pushes from inside go over ssh, behind the agent
  popup.
- **Updates.** The default branch is cached for up to an hour
  (`tarball-ttl`; `nix run --refresh` fetches it now). A pinned commit never
  changes; bump the rev (and `narHash`) to update.
- **One configuration for everyone.** There's no per-user layer: personal
  settings (binds, extra packages, your ssh agent socket) need the
  home-manager module instead. `homeManager.enable = true` still links each
  user's own home-manager files (shell, git config) into their project
  `$HOME`.

`sandbox.nix` still works on top, for settings the project's code may
change; this flake is for what must stay out of its reach.

**gh and fj** aren't provided: bring them like any other tool, in the
project's dev shell, `~/.nix-profile` or home-manager. Whichever one runs
reaches the guards the same way, through the router (below), so no wrapper
or `PATH` order matters.

**The router.** With the GitHub or Forgejo guard on, every process inside
gets `HTTPS_PROXY` pointing at a small router on the sandbox's own loopback,
started before your command. It sends `CONNECT`s for the GitHub API hosts to
gh-api-proxy, for Forgejo instances with a token to forgejo-api-proxy, and
everything else straight out over the sandbox's network, as without a
proxy. `SSL_CERT_FILE`, `NIX_SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` add the
guards' CAs, so any client completes TLS with them; `NO_PROXY` keeps loopback
direct, for dev servers. Clients that ignore `HTTPS_PROXY` simply bypass it
(and reach the APIs without a token). A host `HTTPS_PROXY` passed in with
`passEnv` is replaced: the router dials out directly.

## Configuration

All options are in [nix/module.nix](nix/module.nix). The main ones:

| Option | Default | |
| --- | --- | --- |
| `packages` | `[ ]` | Extra packages on `PATH` inside. |
| `basePackages` | small userland | Replace to trim or swap the base set. |
| `env` | `{ }` | Variables inside; `~`, `$HOME`, `$USER`, `$XDG_RUNTIME_DIR` expanded. |
| `passEnv` | `[ ]` | Host variables passed in, besides TERM/COLORTERM/LANG/LC_ALL. |
| `binds` | `[ ]` | Host paths bound in: `{ src; dst; mode = "ro" \| "rw"; optional; hideGit; }`; one whose src is the project is left to the project bind. |
| `hostPorts` | `[ ]` | Like `SANDBOX_HOST_PORTS`, always. |
| `stateDir` | `$XDG_DATA_HOME/sandbox` | One folder per project: its `$HOME`, tokens and keys, Secret Service data, exchange dir. `$SANDBOX_STATE_DIR` overrides. |
| `nixLd.libraries` | libstdc++, zlib, openssl, curl | For prebuilt binaries. |
| `nixConfig` | flakes on | `NIX_CONFIG` inside; there is no nix.conf in there. |
| `nixProfile.enable` | on | Link the host's `~/.nix-profile` in and put its `bin/` on `PATH`, after the sandbox's own. |
| `homeManager.enable` | off (on with the home-manager module) | Link your current home-manager generation into each project's `$HOME` at every start. |
| `locales` | C.UTF-8, en_US.UTF-8 | glibcLocales build for `LOCALE_ARCHIVE`; override to add yours. |
| `guards.sshAgent` | on, `$SSH_AUTH_SOCK` | `socket` (host) and `path` (inside). See [SSH agent](#ssh-agent). |
| `guards.github.enable` | on | Needs `sandbox --gh-token` per project, or `gh auth login` on the host. |
| `guards.forgejo.enable` | off | Needs `sandbox --fj-token HOST` per project, or `fj --host HOST auth login` on the host. |
| `guards.claudeApiKey.enable` | off | Claude Code on a per-project API key held outside; a profile can override it. See [Authentication](#authentication). |
| `guards.openUrl.enable` | on | `xdg-open` inside opens http(s) URLs in the host's browser, after a popup. |
| `guards.secretService.enable` | on | A per-project Secret Service on a private D-Bus, for tools using libsecret. |
| `claude.enable` / `.package` | on / `pkgs.claude-code` | `package = null` keeps the managed config but brings no `claude`: one from the dev shell, `~/.nix-profile` or home-manager runs instead. |
| `claude.settings` | autoupdater off, a hook steering GitHub HTTP requests to `gh` | managed-settings.json, merged across modules. |
| `claude.memory` | sandbox, GitHub, Forgejo notes | Managed CLAUDE.md; your lines are appended. |
| `claude.mcpServers` | `{ }` | Managed MCP servers (exclusive: a project's .mcp.json is then ignored). |
| `claude.lspServers.<name>` | `{ }` | `{ package; command; args; extensionToLanguage; settings; }`: language servers as enabled plugins of a generated `sandbox` marketplace in the store. |
| `claude.marketplaces.<name>` | `{ }` | Plugin marketplace directories (store paths); enable their plugins in `claude.settings.enabledPlugins`. |
| `profiles.<name>` | | Per-project additions, see below. |

### Plugins and language servers

Plugins come from marketplaces in the store, pinned like
everything else, not from git checkouts that update themselves in each
project's `$HOME`:

```nix
claude.lspServers = {
  gopls = { package = pkgs.gopls; extensionToLanguage.".go" = "go"; };
  ty = {
    package = pkgs.ty;
    args = [ "server" ];
    extensionToLanguage = { ".py" = "python"; ".pyi" = "python"; };
  };
};
claude.marketplaces.mine = ./my-marketplace;   # .claude-plugin/marketplace.json
claude.settings.enabledPlugins."some-plugin@mine" = true;
```

Once any marketplace or language server is set, these are the only
marketplaces Claude Code knows: they're
registered in each project's `$HOME` before its first session (so enabled plugins work
from the start), and the official marketplace and `/plugin marketplace add`
are refused.

### Profiles

A profile applies when the sandbox starts under one of its `paths`, or in a
project whose root has one of its `projectFiles`. Only one applies: the
matching one with the highest `priority` (the first by name on a tie), so
profiles don't combine with each other. It adds `binds` and `claude.*`
(language servers and marketplaces included) on top of the top level, and
can turn `guards.claudeApiKey.enable` on or off. `packages` and `env` are
top-level only, the same in every project.

```nix
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
```

## Development

```sh
make test              # everything: all tests against a fresh build, and lint
make test RUN=HostPort # only the tests matching a go test -run filter, no lint
make coverage          # line coverage of the Go code by the tests
make fmt               # format Go and nix files
```

The launcher, init and the guards are subcommands of one Go binary,
`sandbox-bin` (`cmd/sandbox-bin`, `internal/`); `sandbox-bin --help` lists
them, and the `sandbox` command is a wrapper around `sandbox-bin launch`
with its configuration. Each package has its tests next to it; the
launcher's and init's also run the binary's subcommands, and `e2e/` starts
real sandboxes from a fresh build.

Each target enters the dev shell itself when run outside it. The real-sandbox
tests need unprivileged user namespaces, so they skip inside a running
sandbox: run `make test` on the host for the full suite.
