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
  a tmux popup on the host:
  - your ssh agent (commit signing passes without a popup);
  - GitHub through `gh`, with the host's token kept outside;
  - Forgejo through `fj` (opt-in);
  - opening http(s) URLs in the host's browser.
- **A Secret Service** per project, so tools storing credentials via libsecret
  work without a desktop keyring.
- **An exchange dir** (`$SANDBOX_EXCHANGE`), read-only inside, for output of
  commands you run on the host.
- **Claude Code** with managed settings and a `CLAUDE.md` that tells it about
  all of the above.

See [SECURITY.md](SECURITY.md) for the threat model.

Requirements: Linux with unprivileged user namespaces, nix with a daemon
(multi-user install). Popups need the sandbox started inside tmux; without
it every guarded request is refused.

## Install

```sh
nix profile add github:mgnsk/sandbox
```

That's all a project needs: `sandbox` is one command for every project, and a
project brings its own tools through its flake or a `sandbox.nix` (below). For home-manager and
custom builds, see [Configuring the sandbox](#configuring-the-sandbox).

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

### The project's own sandbox config: sandbox.nix

A `sandbox.nix` in the project root configures that project's sandbox, on
top of yours - like `devenv.nix`, a module that gets `pkgs`:

```nix
{ pkgs, ... }:
{
  packages = [ pkgs.go pkgs.golangci-lint ];
  env.GOFLAGS = "-mod=mod";
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

It can set `packages` (first on `PATH`), `env`, `command`, `claude.*`
(settings, memory, MCP and language servers, marketplaces), `hostPorts` and
`binds`. `pkgs` is the sandbox's own nixpkgs; to use the project's pinned
one, import it yourself, e.g.
`(builtins.getFlake (toString ./.)).inputs.nixpkgs.legacyPackages.${pkgs.stdenv.hostPlatform.system}`.

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

```nix
# sandbox.nix, next to devenv.nix
{ pkgs, ... }:
{
  packages = [ pkgs.devenv ];
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
  (languages, packages, services); sandbox.nix describes the sandbox around
  it (host ports, binds, Claude config). Tools only devenv's shell needs
  belong in devenv.nix; put something in sandbox.nix `packages` only if it
  should be on `PATH` outside the devenv shell too.
- **Services are inside.** A Postgres or Redis from `services.*` runs in the
  sandbox, so the project reaches it on `127.0.0.1` without `hostPorts`
  (that's for services on the host). Ports bound inside are reachable from
  the host's `127.0.0.1` too, e.g. to open a dev server in your browser.
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
            env.GOPRIVATE = "git.example.com";
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
| `guards.sshAgent` | on, `$SSH_AUTH_SOCK` | `socket` (host) and `path` (inside). |
| `guards.github.enable` | on | Needs `gh auth login` on the host. |
| `guards.forgejo.enable` | off | Needs `fj auth login` on the host. |
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

A profile adds `packages`, `env`, `binds` and `claude.*` (language servers and
marketplaces included) on top of the top
level when the sandbox starts under one of its `paths` or in a project whose
root has one of its `projectFiles`; the highest `priority` wins.

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
nix develop
pytest tests                                  # unit tests; real-sandbox ones skip
SANDBOX_BIN=$(nix build --print-out-paths)/bin/sandbox pytest tests   # on a real host
nix flake check                               # the unit tests, as a nix build
ruff check . && ruff format --check .         # lint and formatting
```

The real-sandbox tests need unprivileged user namespaces, so they skip inside
a running sandbox.
