# The sandbox every project of the demo gets (the options are in the
# sandbox's OPTIONS.md).
{ pkgs, lib, ... }:
{
  # In every project, whatever its dev shell brings.
  packages = [ pkgs.gh ];

  # Name, email and signing key from the user's git config on the host,
  # since a project's $HOME inside starts without one.
  git.fromHost = true;

  claude = {
    enable = true;
    memory = ''
      # Demo

      This is the sandbox's demo: the project is a small Go program.
    '';
    mcpServers.mcp-nixos = {
      type = "stdio";
      command = lib.getExe pkgs.mcp-nixos;
    };
    lspServers.gopls = {
      package = pkgs.gopls;
      extensionToLanguage.".go" = "go";
    };
  };

  # The API guards run once they have a token command, run on the host at
  # each start; the token never enters the sandbox. E.g.:
  #   guards.github.tokenCommand = "${lib.getExe pkgs.gh} auth token";
}
