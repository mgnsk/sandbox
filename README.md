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
  (`~/.local/share/sandbox/<project>`); only the project directory itself is
  the host's, read-write.
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

Standalone:

```sh
nix profile add github:mgnsk/sandbox
```

With home-manager:

```nix
{
  inputs.sandbox.url = "github:mgnsk/sandbox";
  inputs.sandbox.inputs.nixpkgs.follows = "nixpkgs";
  # ...
  modules = [
    inputs.sandbox.homeManagerModules.default
    {
      programs.sandbox.enable = true;
      programs.sandbox.settings = {
        packages = [ pkgs.go pkgs.nodejs ];
      };
    }
  ];
}
```

The home-manager module also links your current home-manager generation into
each project's `$HOME` at every start (`homeManager.enable`), so your shell
config, git config, etc. apply inside.

Or build a configured package yourself:

```nix
sandbox.lib.mkSandbox {
  inherit pkgs;
  modules = [ { guards.forgejo.enable = true; } ];
}
```

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
| `binds` | `[ ]` | Host paths bound in: `{ src; dst; mode = "ro" \| "rw"; optional; hideGit; writableWhenProject; }`. |
| `hostPorts` | `[ ]` | Like `SANDBOX_HOST_PORTS`, always. |
| `stateDir` | `$XDG_DATA_HOME/sandbox` | Volumes, secrets, exchange dirs. `$SANDBOX_STATE_DIR` overrides. |
| `nixLd.libraries` | libstdc++, zlib, openssl, curl | For prebuilt binaries. |
| `guards.sshAgent` | on, `$SSH_AUTH_SOCK` | `socket` (host) and `path` (inside). |
| `guards.github.enable` | on | Needs `gh auth login` on the host. |
| `guards.forgejo.enable` | off | Needs `fj auth login` on the host. |
| `guards.openUrl.enable` | on | |
| `guards.secretService.enable` | on | |
| `claude.enable` / `.package` | on / `pkgs.claude-code` | |
| `claude.settings` | autoupdater off, GitHub hook | managed-settings.json, merged across modules. |
| `claude.memory` | sandbox, GitHub, Forgejo notes | Managed CLAUDE.md; your lines are appended. |
| `claude.mcpServers` | `{ }` | Managed MCP servers (exclusive: a project's .mcp.json is then ignored). |
| `profiles.<name>` | | Per-project additions, see below. |

### Profiles

A profile adds `packages`, `env`, `binds` and `claude.*` on top of the top
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
```

The real-sandbox tests need unprivileged user namespaces, so they skip inside
a running sandbox.
