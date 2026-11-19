{
  description = "sandbox: run coding agents and project builds in a per-project bwrap + pasta sandbox, entirely from nix";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f (pkgsFor system));

      pkgsFor = system: nixpkgs.legacyPackages.${system};

      # A `sandbox` package from configuration modules (see nix/module.nix
      # for the options), e.g.
      #   sandbox.lib.mkSandbox { inherit pkgs; modules = [ { guards.forgejo.enable = true; } ]; }
      evalSandbox = import ./nix/eval.nix { inherit lib; };
      mkSandbox = args: (evalSandbox args).package;
    in
    {
      lib = { inherit mkSandbox evalSandbox; };

      # programs.sandbox for home-manager.
      homeManagerModules.default = import ./nix/hm-module.nix { inherit evalSandbox; };

      # The sandbox with default settings, run from this flake's remote:
      #   nix run github:mgnsk/sandbox[/REV] -- COMMAND...
      # It reads no user config; settings of your own come from home-manager
      # (homeManagerModules) or a flake with mkSandbox (see the README).
      packages = forAllSystems (pkgs: {
        default = mkSandbox { inherit pkgs; };
      });

      checks = forAllSystems (pkgs: {
        tests = pkgs.callPackage ./nix/tests.nix { };
        project = pkgs.callPackage ./nix/project-check.nix { };
        config = pkgs.callPackage ./nix/config-check.nix { inherit evalSandbox; };
        default = mkSandbox { inherit pkgs; };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go
            # gh and fj, which the proxy tests run, and the bus the
            # secret-service tests start.
            pkgs.gh
            pkgs.forgejo-cli
            pkgs.dbus
            # What the real-sandbox tests (e2e) run inside, by store path:
            # the sandbox itself has none of them.
            pkgs.python3
            pkgs.curl
            pkgs.iproute2
            pkgs.getent
            # libseccomp for internal/seccomp, the one cgo package.
            pkgs.pkg-config
            pkgs.libseccomp
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
