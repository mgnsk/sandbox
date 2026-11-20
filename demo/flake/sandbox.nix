# The sandbox around this project. The tools inside, Claude Code included,
# come from the dev shell in flake.nix; this only shapes the sandbox. The
# first start shows what it asks of the host (here git.fromHost) for
# approval.
{ pkgs, ... }:
let
  # The project's pinned nixpkgs (flake.lock) rather than the sandbox's own,
  # so Claude Code's language server is the dev shell's gopls.
  inherit (pkgs.stdenv.hostPlatform) system;
  projectPkgs = (builtins.getFlake (toString ./.)).inputs.nixpkgs.legacyPackages.${system};
in
{
  # What a bare `sandbox` runs: the dev shell, not a plain login shell.
  command = [
    "nix"
    "develop"
  ];

  # Name, email and signing key from each user's git config on the host,
  # since the project's $HOME inside starts without one.
  git.fromHost = true;

  # Lookups of nixpkgs packages and options, for work on flake.nix. Managed
  # MCP servers are exclusive: a .mcp.json in the project is then ignored.
  claude.mcpServers.mcp-nixos = {
    type = "stdio";
    command = pkgs.lib.getExe projectPkgs.mcp-nixos;
  };

  claude.lspServers.gopls = {
    package = projectPkgs.gopls;
    extensionToLanguage.".go" = "go";
  };

  claude.settings.permissions.allow = [
    "Bash(go build:*)"
    "Bash(go test:*)"
    "mcp__mcp-nixos__nix"
  ];

  # Also possible here, each approved by the user on the terminal:
  #   guards.github.tokenCommand = "op read op://Employee/GitHub/token";
  #   guards.wayland.enable = true;   # GUI programs, e.g. VS Code
  #   hostPorts = [ "5432" ];         # a database on the host
}
