# A user's sandbox settings, for nix/config-check.nix.
{ pkgs, ... }:
{
  packages = [ pkgs.hello ];
  env.EDITOR = "nvim";
  hostPorts = [ "5432" ];
  guards.forgejo.enable = true;
  profiles.work = {
    paths = [ "~/work" ];
    guards.claudeApiKey.tokenCommand = "op read op://v/claude/key";
  };
}
