# The sandbox's PreToolUse hooks (agent-hooks/), for one agent's hook
# format: `agent` is claude or antigravity, which lib.sh reads the call and
# writes the decision for. Gives the executable of the hook `name`.
{ lib, pkgs }:
agent: name:
lib.getExe (
  pkgs.writeShellApplication {
    name = "${agent}-${name}";
    runtimeInputs = [
      pkgs.jq
      pkgs.gnugrep
      pkgs.gnused
    ];
    text = ''
      agent=${agent}
      ${builtins.readFile ./agent-hooks/lib.sh}
      ${builtins.readFile ./agent-hooks/${name}.sh}
    '';
  }
)
