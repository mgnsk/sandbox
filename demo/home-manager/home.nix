# The user's own environment, which the home-manager-installed sandbox
# brings into every project: this generation is linked into each project's
# $HOME at every start, and ~/.nix-profile/bin is on PATH inside.
{ pkgs, lib, ... }:
{
  home.username = "tester";
  home.homeDirectory = "/home/tester";
  home.stateVersion = "25.11";

  programs.home-manager.enable = true;

  # Tools for every project, with or without a dev shell of its own.
  home.packages = [
    pkgs.gh
    pkgs.tree
  ];

  # Claude Code in every project, linked into each one's $HOME as
  # ~/.claude. A project whose flake brings its own (sandbox.lib.mkShell's
  # claude) uses that one instead, with a config dir of its own: none of
  # this applies there.
  programs.claude-code = {
    enable = true;
    settings = {
      theme = "auto";
      permissions.allow = [
        "Bash(tree:*)"
        "mcp__mcp-nixos__nix"
      ];
    };
    # The running sandbox's AGENTS.md (what it is, which guards run), then
    # your own.
    context = ''
      @/etc/sandbox/AGENTS.md

      # Demo

      This is the sandbox's home-manager demo: the user's config is
      read-only at ~/.config/home-manager.
    '';
    mcpServers.mcp-nixos = {
      type = "stdio";
      command = lib.getExe pkgs.mcp-nixos;
    };
    lspServers.nil = {
      command = lib.getExe pkgs.nil;
      extensionToLanguage.".nix" = "nix";
    };
  };

  # Shell and git config, the same on the host and inside: no "Author
  # identity unknown" in a fresh project $HOME.
  programs.bash = {
    enable = true;
    shellAliases.ll = "ls -l";
  };
  programs.git = {
    enable = true;
    settings = {
      user.name = "Demo Tester";
      user.email = "tester@example.com";
      init.defaultBranch = "main";
    };
  };

  programs.sandbox = {
    enable = true;
    # Your sandbox config: it applies to every project and, unlike a
    # project's flake, is trusted - nothing in it asks for approval.
    # See the options in the sandbox's README.
    settings = {
      # Host variables passed in; everything else is cleared.
      passEnv = [ "EDITOR" ];

      # This config, read-only and without its history, in every project.
      binds = [
        {
          src = "~/.config/home-manager";
          hideGit = true;
          optional = true;
        }
      ];

      # The API guards run once they have a token command, run on the host
      # at each start; the token never enters the sandbox. E.g.:
      #   guards.github.tokenCommand = "${lib.getExe pkgs.gh} auth token";
      #   guards.forgejo.tokenCommands."codeberg.org" = "op read op://v/cb/token";
    };
  };
}
