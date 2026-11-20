# A user's sandbox settings, for nix/config-check.nix.
{ ... }:
{
  hostPorts = [ "5432" ];
  guards.wayland.globals.zwp_tablet_manager_v2 = false;
  profiles.work = {
    paths = [ "~/work" ];
    guards.claudeApiKey.tokenCommand = "op read op://v/claude/key";
  };
}
