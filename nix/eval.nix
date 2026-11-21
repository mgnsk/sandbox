# The sandbox's configuration from modules (see module.nix for the options):
# for the flake's default package, and the home-manager module.
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
