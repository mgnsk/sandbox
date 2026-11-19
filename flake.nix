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

      # claude-code is unfree; nothing else here is.
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          config.allowUnfreePredicate = pkg: lib.getName pkg == "claude-code";
        };

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

      # No `sandbox` package of its own: build it with mkSandbox, from
      # home-manager (homeManagerModules) or a project's flake run from its
      # remote (see the README).

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
            # libseccomp for internal/seccomp, the one cgo package.
            pkgs.pkg-config
            pkgs.libseccomp
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
