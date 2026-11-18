# The sandbox's configuration from modules (see module.nix for the options):
# lib.evalSandbox in the flake, and user.nix.
{ lib }:
{
  pkgs,
  modules ? [ ],
}:
(lib.evalModules {
  modules = [
    ./module.nix
    { _module.args.pkgs = lib.mkDefault pkgs; }
  ]
  ++ modules;
}).config
