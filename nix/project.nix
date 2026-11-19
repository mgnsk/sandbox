# A project's sandbox.nix, as the manifest the launcher reads: run inside a
# sandbox by the launcher as
#   nix build --file project.nix --argstr nixpkgs ... --argstr system ...
#     --argstr file .../sandbox.nix --argstr base <profile's claude dir or "">
# (or called with paths, as the flake's check does). Evaluated in there,
# never on the host: sandbox.nix is the project's, which
# the sandbox can write, and evaluating it on the host would let it read host
# files into the store.
{
  nixpkgs,
  system,
  file,
  base ? "",
}:
let
  pkgs = import nixpkgs { inherit system; };
  inherit (pkgs) lib;
  layer = import ./layer.nix { inherit lib pkgs; };

  cfg =
    (lib.evalModules {
      modules = [
        {
          options = layer.options // {
            hostPorts = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Host loopback ports reachable inside, like the top-level option.";
            };
            command = lib.mkOption {
              type = lib.types.nullOr (lib.types.listOf lib.types.str);
              default = null;
              example = [
                "nix"
                "develop"
              ];
              description = "What `sandbox` with no command runs, in place of a login shell.";
            };
            guards.github.tokenCommand = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "op read op://Employee/GitHub/token";
              description = ''
                A shell command printing the GitHub token, run on the host at
                each start once the user approves it on the terminal (asked
                once, and again whenever it changes). The user's own config
                wins.
              '';
            };
            guards.forgejo.tokenCommands = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = { };
              description = "Shell commands printing each Forgejo host's token, approved like guards.github.tokenCommand.";
            };
          };
        }
        { _module.args.pkgs = lib.mkDefault pkgs; }
        (if builtins.isPath file then file else /. + file)
      ];
    }).config;

  claude =
    let
      v = layer.claudeValues {
        inherit (cfg) claude;
        lspMarketplace = "project";
      };
    in
    v
    // {
      # A server the project defines replaces the profile's of that name,
      # rather than both claiming its files.
      settings = lib.recursiveUpdate v.settings {
        enabledPlugins = lib.mapAttrs' (n: _: lib.nameValuePair "${n}@sandbox" false) cfg.claude.lspServers;
      };
    };
in
layer.json.generate "sandbox-project.json" {
  inherit (cfg) hostPorts command;
  githubTokenCommand = cfg.guards.github.tokenCommand;
  forgejoTokenCommands = cfg.guards.forgejo.tokenCommands;
  binds = map (b: {
    inherit (b)
      src
      dst
      mode
      optional
      hideGit
      ;
  }) cfg.binds;
  # The profile's managed config with the project's on top; none without
  # Claude Code in the sandbox.
  claudeDir =
    if base == "" then
      null
    else
      let
        base' = builtins.storePath base;
      in
      "${layer.claudeDir "project" (layer.mergeClaudeValues (layer.readClaudeDir base') claude) {
        dependsOn = [ base' ];
      }}";
}
