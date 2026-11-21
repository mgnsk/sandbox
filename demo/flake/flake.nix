# A project that brings everything inside the sandbox through its own dev
# shell - Claude Code, gh, Go and its language server - and shapes the
# sandbox around it in the same place: sandbox.lib.mkShell's `sandbox`. The
# first start shows what it asks of the host (here git.fromHost) for
# approval.
{
  description = "sandbox demo: a Go project with a flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    # Only for lib.mkShell and lib.mkClaude: the sandbox that runs the
    # project is the user's own, whatever version this pins.
    sandbox = {
      url = "github:mgnsk/sandbox";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, sandbox, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              # Claude Code is unfree.
              config.allowUnfreePredicate = p: nixpkgs.lib.getName p == "claude-code";
            }
          )
        );
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.buildGoModule {
          pname = "hello";
          version = "0.0.0";
          src = ./.;
          vendorHash = null;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = sandbox.lib.mkShell {
          inherit pkgs;

          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.golangci-lint
            # The sandbox ships no gh.
            pkgs.gh
          ];

          # The project's variables go here too.
          CGO_ENABLED = "0";

          # The sandbox around this shell. A bare `sandbox` runs
          # `nix develop`.
          sandbox = {
            # Name, email and signing key from each user's git config on
            # the host, since the project's $HOME inside starts without one.
            git.fromHost = true;

            # Also possible here, each approved by the user on the terminal:
            #   guards.github.tokenCommand = "op read op://Employee/GitHub/token";
            #   guards.wayland.enable = true;   # GUI programs, e.g. VS Code
            #   hostPorts = [ "5432" ];         # a database on the host
          };

          # Claude Code, configured by the project alone: a claude of the
          # user's own (home-manager's ~/.claude) doesn't apply in here.
          claude = {
            # Lookups of nixpkgs packages and options, for work on
            # flake.nix. With MCP servers here, a .mcp.json in the project
            # is ignored.
            mcpServers.mcp-nixos = {
              type = "stdio";
              command = pkgs.lib.getExe pkgs.mcp-nixos;
            };

            lspServers.gopls = {
              package = pkgs.gopls;
              extensionToLanguage.".go" = "go";
            };

            settings.permissions.allow = [
              "Bash(go build:*)"
              "Bash(go test:*)"
              "mcp__mcp-nixos__nix"
            ];
          };
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
