# A user's ~/.config/sandbox/config.nix, for nix/user-check.nix.
{ pkgs, ... }:
{
  nixpkgs.config.allowUnfree = true;
  packages = [ pkgs.hello ];
  env.EDITOR = "nvim";
  hostPorts = [ "5432" ];
  guards.forgejo.enable = true;
  profiles.work = {
    paths = [ "~/work" ];
    guards.claudeApiKey.enable = true;
  };
}
