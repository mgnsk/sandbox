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
  # What `nix develop` of this shell does outside a sandbox: "enter" runs
  # the same `nix develop` (or `nix develop -c CMD`) in `sandbox` from PATH,
  # "refuse" stops, "run" goes on, on the host. Not a boundary: the hook
  # that does it is in the flake, which the sandbox can edit.
  onHost ? "enter",
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
    "onHost"
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
      assert lib.assertMsg (lib.elem onHost [
        "enter"
        "refuse"
        "run"
      ]) "sandbox.lib.mkShell: onHost is enter, refuse or run, not ${onHost}";
      # SANDBOX_EXCHANGE is set by the sandbox.
      lib.optionalString (onHost != "run") (
        ''
          if [ -z "''${SANDBOX_EXCHANGE-}" ]; then
        ''
        + lib.optionalString (onHost == "enter") ''
          # nix develop has exec'd `bash RCFILE` (with a command) or
          # `bash --rcfile RCFILE`: after this hook, RCFILE removes itself
          # and execs the command, shell-quoted, if there's one. Anything
          # else (direnv, nix print-dev-env) isn't entered.
          __sandbox_enter() {
            local -a argv
            local rc line i after="" cmd=""
            mapfile -d "" argv </proc/$$/cmdline || return
            rc=''${argv[-1]}
            for i in "''${!argv[@]}"; do
              if [ "''${argv[i]}" = --rcfile ]; then
                rc=''${argv[i + 1]-}
              fi
            done
            case $rc in
            /*/nix-shell.*) ;;
            *) return ;;
            esac
            command -v sandbox >/dev/null || return
            while IFS= read -r line; do
              case $line in
              "command rm -f "*) after=1 ;;
              "exec "*)
                if [ -n "$after" ]; then
                  cmd=''${line#exec }
                  break
                fi
                ;;
              esac
            done <"$rc"
            command rm -f -- "$rc"
            echo "nix develop: entering the sandbox" >&2
            eval "exec sandbox nix develop ''${cmd:+-c $cmd}"
          }
          __sandbox_enter
        ''
        + ''
            echo "nix develop: not in the sandbox: run \`sandbox\` here" >&2
            exit 1
          fi
        ''
      )
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
