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

      # The configuration from modules (see nix/module.nix for the options).
      evalSandbox = import ./nix/eval.nix { inherit lib; };
      mkSandbox = args: (evalSandbox args).package;
    in
    {
      # A `sandbox` command from configuration modules - the tools every
      # project gets inside (Claude Code, VS Code, ...), the guards, binds -
      # for a distribution of the sandbox to install, e.g. an organisation's
      # tools flake:
      #   packages.sandbox = sandbox.lib.mkSandbox { inherit pkgs; modules = [ ./sandbox ]; };
      # pkgs must allow what's unfree among the packages (claude-code,
      # antigravity-cli, vscode). The options are in OPTIONS.md.
      lib = { inherit mkSandbox; };

      checks = forAllSystems (pkgs: {
        tests = pkgs.callPackage ./nix/tests.nix { };
        modules = pkgs.callPackage ./nix/modules-check.nix { inherit evalSandbox; };
        config = pkgs.callPackage ./nix/config-check.nix { inherit evalSandbox; };
        options = pkgs.callPackage ./nix/options-doc.nix { };
        default = mkSandbox { inherit pkgs; };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go
            # make lint and make vuln. actionlint runs shellcheck on the
            # workflows' scripts.
            pkgs.go-tools
            pkgs.govulncheck
            pkgs.actionlint
            pkgs.shellcheck
            # gh and fj, which the proxy tests run, and the bus and
            # secret-tool (libsecret's client) the secret-service tests
            # start.
            pkgs.gh
            pkgs.forgejo-cli
            pkgs.dbus
            pkgs.libsecret
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
