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
  guards.github.tokenCommand = "op read op://v/gh/token";
  guards.forgejo.tokenCommands."codeberg.org" = "op read op://v/cb/token";
  claude.lspServers.gopls = {
    package = pkgs.gopls;
    extensionToLanguage.".go" = "go";
  };
}
