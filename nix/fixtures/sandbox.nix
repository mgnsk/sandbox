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
  guards.claudeApiKey.tokenCommand = "op read op://v/claude/key";
  git.signingKeyCommand = "op read op://v/ssh/public-key";
  git.fromHost = true;
  claude.lspServers.gopls = {
    package = pkgs.gopls;
    extensionToLanguage.".go" = "go";
  };
}
