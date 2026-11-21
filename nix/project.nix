# A project's flake.nix, as the manifest the launcher reads: run inside a
# sandbox by the launcher as
#   nix build --file project.nix --argstr nixpkgs ... --argstr system ...
#     --argstr flake <project dir>
# Evaluated in there, never on the host: the flake is the project's, which
# the sandbox can write, and evaluating it on the host would let it read
# host files into the store.
#
# The configuration is the default dev shell's `sandbox` (sandbox.lib.mkShell
# puts it there): a module, evaluated with this sandbox's options, not with
# those of the sandbox the flake pins. Without one, the defaults.
{
  nixpkgs,
  system,
  flake,
}:
let
  pkgs = import nixpkgs { inherit system; };
  shell = (builtins.getFlake flake).devShells.${system}.default or { };
in
import ./manifest.nix {
  inherit pkgs;
  module = shell.sandbox or { };
}
