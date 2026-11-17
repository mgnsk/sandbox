{
  description = "sandbox: run coding agents and project builds in a per-project bwrap + pasta sandbox, entirely from nix";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs =
    { self, nixpkgs }:
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
      mkSandbox =
        {
          pkgs,
          modules ? [ ],
        }:
        (lib.evalModules {
          modules = [
            ./nix/module.nix
            { _module.args.pkgs = pkgs; }
          ]
          ++ modules;
        }).config.package;
    in
    {
      lib = { inherit mkSandbox; };

      # programs.sandbox for home-manager.
      homeManagerModules.default = import ./nix/hm-module.nix { inherit mkSandbox; };

      packages = forAllSystems (pkgs: {
        default = mkSandbox { inherit pkgs; };
        inherit (pkgs.callPackage ./nix/packages.nix { }) gh forgejo-cli;
      });

      checks = forAllSystems (pkgs: {
        tests = pkgs.callPackage ./nix/tests.nix { };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      });

      devShells = forAllSystems (pkgs: {
        default =
          let
            p = pkgs.callPackage ./nix/packages.nix { };
          in
          pkgs.mkShell {
            packages = [
              (pkgs.python3.withPackages (ps: [
                ps.dbus-fast
                ps.graphql-core
                ps.pytest
              ]))
              p.gh
              p.forgejo-cli
              pkgs.ruff
              pkgs.procps
            ];
          };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
