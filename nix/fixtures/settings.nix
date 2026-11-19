# A user's sandbox settings, for nix/config-check.nix.
{ ... }:
{
  hostPorts = [ "5432" ];
  profiles.work = {
    paths = [ "~/work" ];
    guards.claudeApiKey.tokenCommand = "op read op://v/claude/key";
  };
}
