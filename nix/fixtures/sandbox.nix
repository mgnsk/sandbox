# A project's sandbox.nix, for nix/project-check.nix.
{ pkgs, ... }:
{
  hostPorts = [ "5432" ];
  binds = [
    {
      src = "~/data";
      mode = "rw";
    }
  ];
  command = [
    "nix"
    "develop"
  ];
  claude.lspServers.gopls = {
    package = pkgs.gopls;
    extensionToLanguage.".go" = "go";
  };
}
