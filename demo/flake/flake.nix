# A project that brings everything inside the sandbox through its own dev
# shell: Claude Code, gh, Go and its language server. The sandbox around it
# is configured in sandbox.nix.
{
  description = "sandbox demo: a Go project with a flake";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs =
    { nixpkgs, ... }:
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
        default = pkgs.mkShell {
          packages = [
            # First on PATH: the dev shell's own bash has no readline or
            # completion.
            pkgs.bashInteractive

            pkgs.go
            pkgs.gopls
            pkgs.golangci-lint

            # The sandbox ships neither.
            pkgs.claude-code
            pkgs.gh
          ];

          # The project's variables go here too.
          CGO_ENABLED = "0";

          shellHook = ''
            # The dev shell is for the sandbox only: outside it, Claude Code
            # would have the whole home directory. SANDBOX_EXCHANGE is set
            # by the sandbox.
            if [ -z "''${SANDBOX_EXCHANGE-}" ]; then
              echo "nix develop: not in the sandbox: run \`sandbox\` here" >&2
              exit 1
            fi
            # nix develop points SHELL at the dev shell's plain bash.
            export SHELL=${pkgs.lib.getExe pkgs.bashInteractive}
          '';
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
