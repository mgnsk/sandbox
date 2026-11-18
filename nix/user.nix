# The user's ~/.config/sandbox/config.nix, as the config the launcher runs
# with: built on the host by the launcher of the flake's default package as
#   nix-build user.nix --argstr nixpkgs ... --argstr system ... --argstr file .../config.nix
# (or called with paths, as the flake's check does). The file is the
# user's own, outside every project, so unlike sandbox.nix it's trusted
# like a home-manager config and evaluated on the host.
{
  nixpkgs,
  system,
  file,
}:
let
  inherit (import nixpkgs { inherit system; }) lib;
  cfg = import ./eval.nix { inherit lib; } {
    pkgs = null;
    modules = [
      (
        { config, ... }:
        {
          options.nixpkgs.config = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
            example = lib.literalExpression "{ allowUnfree = true; }";
            description = "nixpkgs config for `pkgs`. claude-code is allowed as unfree either way.";
          };
          config._module.args.pkgs = import nixpkgs {
            inherit system;
            config =
              let
                own = config.nixpkgs.config;
              in
              own
              // {
                allowUnfreePredicate =
                  p: lib.getName p == "claude-code" || (own.allowUnfreePredicate or (_: false)) p;
              };
          };
        }
      )
      (if builtins.isPath file then file else /. + file)
    ];
  };
in
cfg.configFile
