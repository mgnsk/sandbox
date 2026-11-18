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

- **Its own `$HOME`**, a persistent volume under the state dir
  (`~/.local/share/sandbox/<project>`); only the project directory itself (the
  enclosing git work tree, or `$PWD` outside one) is the host's, read-write.
- **No host userland.** `PATH` is a nix package set (bash, coreutils, git,
  openssh, curl, python3, nix, claude, ...), plus `~/.nix-profile/bin`.
  `/bin/sh`, `/usr/bin/env` and nix-ld for prebuilt binaries are provided.
- **Nix builds** through the host's daemon (`/nix` is read-only inside).
- **Network** out, but not to the host's own services, except ports listed in
  `SANDBOX_HOST_PORTS` (`5037 8080/udp 9000-9010`). Ports bound inside are
  reachable from the host's `127.0.0.1` (dev servers, OAuth callbacks).
- **Guarded host access**, each request (or "always, for this sandbox") behind
  a popup on the terminal the sandbox runs in:
  - your ssh agent (commit signing passes without a popup);
  - GitHub through `gh`, with the host's token kept outside;
  - Forgejo through `fj` (opt-in);
  - the Claude API on a per-project API key (opt-in);
  - opening http(s) URLs in the host's browser.
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

## Install

```sh
nix profile add github:mgnsk/sandbox
```

That's all a project needs: `sandbox` is one command for every project, and a
project brings its own tools through its dev shell (a flake or devenv,
below). For home-manager and custom builds, see [Configuring the sandbox](#configuring-the-sandbox).

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

With direnv, `use flake` in `.envrc` does the same whenever you `cd` in,
provided `direnv` is installed (`packages = [ pkgs.direnv pkgs.nix-direnv ]`).

The project's `$HOME` (`~/go/pkg`, `~/.cache`, Claude's `~/.claude`, ...)
persists between runs in its volume; nothing in it is shared with your real
home or with other projects.

### Authentication

**gh and fj** are logged in on the host, once, outside any sandbox:

```sh
gh auth login    # on the host
fj auth login    # on the host, only with guards.forgejo.enable
```

Inside, `gh` and `fj` talk to their APIs through host proxies that add the
host's token to each request (writes behind a popup); the token itself never
enters the sandbox. Don't run `gh auth login` or `fj auth login` inside: there
is nothing to log in to there, and a token stored inside would bypass the
proxy and its popups. The gh proxy reads the host's token when the sandbox
starts, so after logging in again on the host (or switching accounts) restart
the sandbox; fj's proxy reads it per request.

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
   on the terminal (hidden input) and keeps it in the project's volume dir,
   outside the sandbox.
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

### 1Password's SSH agent

The ssh agent guard proxies whichever agent `$SSH_AUTH_SOCK` points to when
the sandbox starts; for 1Password that's `~/.1password/agent.sock` (Settings →
Developer → Use the SSH agent). With `SSH_AUTH_SOCK` set to that on the host,
the defaults work; set `guards.sshAgent.socket` only if you start `sandbox`
from somewhere it isn't set.

Inside, `SSH_AUTH_SOCK` points at the guard's proxy. If your shell config sets
`SSH_AUTH_SOCK` unconditionally (e.g. home-manager session variables, which
the shell inside sources too with `homeManager.enable`), it overrides that.
Either keep a value that's already set:

```nix
home.sessionVariables.SSH_AUTH_SOCK = "\${SSH_AUTH_SOCK:-$HOME/.1password/agent.sock}";
```

or put the proxy where your config points:

```nix
guards.sshAgent.path = "~/.1password/agent.sock";
```

Inside, only the guard's proxy is visible, never the real socket. A sign
request (an ssh login, `git push` over ssh) gets the sandbox's popup first,
except git commit and tag signatures; 1Password's own approval on the host
still applies on top, as for any client.

**Commit signing:** use `gpg.format = ssh` with `user.signingKey` set to the
public key itself (`ssh-ed25519 AAAA...`), so `ssh-keygen` signs through the
agent. 1Password's `gpg.ssh.program = op-ssh-sign` talks to the app directly
rather than through the agent socket, and the app isn't reachable inside.

**`op` (the 1Password CLI)** can't use the desktop app integration inside. The
app only accepts `op` running setgid as the `onepassword-cli` group, and
setuid/setgid does nothing in the sandbox (`no_new_privs`), so binding the
app's sockets in wouldn't help either. A manual `op account add` or a service
account token (`OP_SERVICE_ACCOUNT_TOKEN`) would work, but that puts a
1Password credential inside the sandbox, where the project's code can read it.
Use `op` on the host instead.

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
servers, marketplaces), `hostPorts` and `binds`. Not `packages` or `env`:
the project's tools and variables belong in its dev shell (a flake's
`devShells`, devenv), which `command` enters, so they're defined once.
Your own tools come from your sandbox config, `~/.nix-profile` and, with the
home-manager module, your home-manager generation. `pkgs` is the sandbox's
own nixpkgs; to use the project's pinned
one, import it yourself, e.g.
`(builtins.getFlake (toString ./.)).inputs.nixpkgs.legacyPackages.${pkgs.stdenv.hostPlatform.system}`.

A full example, with every option it can set:

```nix
{ pkgs, lib, ... }:
{
  # What a bare `sandbox` runs, in place of a login shell.
  command = [ "nix" "develop" ];

  # Host ports reachable at 127.0.0.1 inside (port, port/udp or a range).
  # Needs your approval on the terminal.
  hostPorts = [ "5432" "9000-9010" ];

  # Host paths bound in, shadowing the project's home volume.
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

- **It's evaluated inside the sandbox** (a nested one, without the project's
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

Its Claude settings go over yours: objects merge, lists (permission rules,
hooks) add up, other values are replaced. A language server it defines
replaces one of yours with the same name.

Don't define the sandbox itself in the project's flake (a
`packages.sandbox = sandbox.lib.mkSandbox { ... }` run with `nix run
.#sandbox`): the sandbox can edit `flake.nix`, and the next `nix run` runs
whatever it put there on the host. `sandbox.nix` is the safe way.

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
- **One sandbox per network.** Each `sandbox` run has its own network
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

  Pass them only to the second sandbox, never through `hostPorts` in
  sandbox.nix. That applies to both sandboxes, and the first one's port
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
  are in the project's volume, so nothing is shared with devenv on the host
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

From your own flake - your system or user config, never a sandboxed project:

```nix
{
  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.sandbox.url = "github:mgnsk/sandbox";
  inputs.sandbox.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { nixpkgs, sandbox, ... }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        config.allowUnfreePredicate = p: nixpkgs.lib.getName p == "claude-code";
      };
    in {
      packages.x86_64-linux.default = sandbox.lib.mkSandbox {
        inherit pkgs;
        modules = [{
          packages = [ pkgs.neovim pkgs.direnv pkgs.nix-direnv ];
          hostPorts = [ "5432" ];               # a host Postgres, always
          guards.forgejo.enable = true;
          profiles.work = {
            paths = [ "~/work" ];
            guards.claudeApiKey.enable = true;
          };
        }];
      };
    };
}
```

```sh
nix profile add ~/my-sandbox-config      # in place of github:mgnsk/sandbox
```

With home-manager:

```nix
modules = [
  inputs.sandbox.homeManagerModules.default
  {
    programs.sandbox.enable = true;
    programs.sandbox.settings = {
      packages = [ pkgs.neovim ];
    };
  }
];
```

The home-manager module also links your current home-manager generation into
each project's `$HOME` at every start (`homeManager.enable`), so your shell
config, git config, etc. apply inside.

`pkgs` must allow the unfree `claude-code`, or set `claude.enable = false`.

`gh` and `fj` inside must be the patched builds (`packages.<system>.gh` and
`.forgejo-cli`): unpatched, they send their placeholder credentials straight
to the API and fail with 401. The sandbox's own come first on `PATH`, but a
login shell that prepends `~/.nix-profile/bin` brings the profile's copy
first. The home-manager module installs the patched ones at high priority
for that; with `nix profile`, install those two from this flake in place of
nixpkgs' `gh`/`forgejo-cli`.

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
| `stateDir` | `$XDG_DATA_HOME/sandbox` | Volumes, secrets, exchange dirs. `$SANDBOX_STATE_DIR` overrides. |
| `nixLd.libraries` | libstdc++, zlib, openssl, curl | For prebuilt binaries. |
| `nixConfig` | flakes on | `NIX_CONFIG` inside; there is no nix.conf in there. |
| `guards.sshAgent` | on, `$SSH_AUTH_SOCK` | `socket` (host) and `path` (inside). See [1Password's SSH agent](#1passwords-ssh-agent). |
| `guards.github.enable` | on | Needs `gh auth login` on the host. |
| `guards.forgejo.enable` | off | Needs `fj auth login` on the host. |
| `guards.claudeApiKey.enable` | off | Claude Code on a per-project API key held outside; a profile can override it. See [Authentication](#authentication). |
| `guards.openUrl.enable` | on | |
| `guards.secretService.enable` | on | |
| `claude.enable` / `.package` | on / `pkgs.claude-code` | |
| `claude.settings` | autoupdater off, GitHub hook | managed-settings.json, merged across modules. |
| `claude.memory` | sandbox, GitHub, Forgejo notes | Managed CLAUDE.md; your lines are appended. |
| `claude.mcpServers` | `{ }` | Managed MCP servers (exclusive: a project's .mcp.json is then ignored). |
| `claude.lspServers.<name>` | `{ }` | `{ package; command; args; extensionToLanguage; settings; }`: language servers as enabled plugins of a generated `sandbox` marketplace in the store. |
| `claude.marketplaces.<name>` | `{ }` | Plugin marketplace directories (store paths); enable their plugins in `claude.settings.enabledPlugins`. |
| `profiles.<name>` | | Per-project additions, see below. |

### Plugins and language servers

Plugins come from marketplaces in the store, pinned by your flake.lock like
everything else, not from git checkouts that update themselves in each
volume:

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

Once any is set, these are the only marketplaces Claude Code knows: they're
registered in every volume before its first session (so enabled plugins work
from the start), and the official marketplace and `/plugin marketplace add`
are refused.

### Profiles

A profile adds `binds` and `claude.*` (language servers and marketplaces
included) on top of the top level, and can turn `guards.claudeApiKey.enable`
on or off, when the sandbox starts under one of its `paths` or in a project
whose root has one of its `projectFiles`; the highest `priority` wins.
`packages` and `env` are top-level only: the same in every project.

```nix
profiles.flake = {
  projectFiles = [ "flake.nix" ];
  claude.mcpServers.mcp-nixos = { type = "stdio"; command = "mcp-nixos"; };
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
make test             # everything: all tests against a fresh build, and lint
make test K=host_port # only the pytest tests matching a -k filter, no lint
make fmt              # format Python and nix files
```

Each target enters the dev shell itself when run outside it. The real-sandbox
tests need unprivileged user namespaces, so they skip inside a running
sandbox: run `make test` on the host for the full suite.
