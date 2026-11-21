# sandbox.lib.mkShell: pkgs.mkShell for a project that's worked on in the
# sandbox, with the sandbox's configuration on it:
#
#   devShells.${system}.default = sandbox.lib.mkShell {
#     inherit pkgs;
#     packages = [ pkgs.go ];
#     sandbox = { git.fromHost = true; };       # a module: OPTIONS.md
#     claude = { settings = { ... }; };         # mkClaude's options
#   };
#
# The launcher evaluates the default dev shell's `sandbox` (passthru) with
# its own options, inside a sandbox of the project: the sandbox the
# project pins is only where this function comes from.
{ lib, mkClaude }:
{
  pkgs,
  # The sandbox's configuration, a module of project-options.nix's options.
  sandbox ? { },
  # mkClaude's options (a module) for Claude Code in the shell; null for
  # none.
  claude ? null,
  # Whether the shell refuses to start outside the sandbox. Only a guard
  # against running it on the host by mistake: the sandbox can edit the
  # flake, so this is no boundary.
  requireSandbox ? true,
  packages ? [ ],
  shellHook ? "",
  passthru ? { },
  ...
}@args:
pkgs.mkShell (
  removeAttrs args [
    "pkgs"
    "sandbox"
    "claude"
    "requireSandbox"
  ]
  // {
    packages = [
      # First on PATH: stdenv's own bash has no readline or completion.
      pkgs.bashInteractive
    ]
    ++ packages
    ++ lib.optional (claude != null) (mkClaude {
      inherit pkgs;
      imports = [ claude ];
    });

    shellHook =
      lib.optionalString requireSandbox ''
        # SANDBOX_EXCHANGE is set by the sandbox.
        if [ -z "''${SANDBOX_EXCHANGE-}" ]; then
          echo "nix develop: not in the sandbox: run \`sandbox\` here" >&2
          exit 1
        fi
      ''
      + ''
        # nix develop points SHELL at stdenv's plain bash.
        export SHELL=${lib.getExe pkgs.bashInteractive}
      ''
      + shellHook;

    passthru = passthru // {
      sandbox = {
        imports = [
          # What a bare `sandbox` runs: this shell.
          {
            command = lib.mkDefault [
              "nix"
              "develop"
            ];
          }
          sandbox
        ];
      };
    };
  }
)
