# The flake's lib: what a project's flake.nix builds its dev shell with.
{ lib }:
let
  claude = import ./claude.nix { inherit lib; };
in
{
  inherit (claude) mkClaude;
  mkShell = import ./shell.nix {
    inherit lib;
    inherit (claude) mkClaude;
  };
}
