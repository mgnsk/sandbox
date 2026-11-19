# programs.sandbox: the `sandbox` command in home.packages, configured from
# any number of home-manager modules through programs.sandbox.settings.
{ evalSandbox }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.sandbox;
  sandbox = evalSandbox {
    inherit pkgs;
    modules = [
      cfg.settings
      { homeManager.enable = lib.mkDefault true; }
    ];
  };
in
{
  options.programs.sandbox = {
    enable = lib.mkEnableOption "the sandbox command";

    settings = lib.mkOption {
      type = lib.types.deferredModule;
      default = { };
      description = ''
        Sandbox configuration (the options in nix/module.nix). Merged across
        modules like any other option, so e.g. one module can add a profile
        while another sets packages.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      description = "The resulting `sandbox` command.";
    };
  };

  config = lib.mkIf cfg.enable {
    programs.sandbox.package = sandbox.package;
    home.packages = [ cfg.package ];
  };
}
