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
    # The linked profile's bin/ can end up before the sandbox's own on PATH
    # inside (e.g. targets.genericLinux sources nix.sh, which prepends it);
    # an unpatched gh or fj there would send the placeholder token straight
    # to the API. High priority, so these win over the profile's own.
    home.packages = [ cfg.package ] ++ map lib.hiPrio sandbox.clientPackages;
  };
}
