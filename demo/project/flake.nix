# A project with its own dev shell: Go and its tools. Nothing in it is about
# the sandbox, which comes from the distribution (../distribution) and
# brings Claude Code itself.
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
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
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
          ];
          # The project's variables go here too.
          CGO_ENABLED = "0";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
