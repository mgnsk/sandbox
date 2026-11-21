# A project's sandbox.nix, as the manifest the launcher reads: run inside a
# sandbox by the launcher as
#   nix build --file project.nix --argstr nixpkgs ... --argstr system ...
#     --argstr file .../sandbox.nix --argstr base <profile's claude dir or "">
#     [--argstr claudeApiKey 1]
# (or called with paths, as the flake's check does). Evaluated in there,
# never on the host: sandbox.nix is the project's, which
# the sandbox can write, and evaluating it on the host would let it read host
# files into the store.
{
  nixpkgs,
  system,
  file,
  base ? "",
  # Claude Code inside runs on an API key whose command isn't sandbox.nix's
  # own (a user's .sandbox.yml sets it): "" for no.
  claudeApiKey ? "",
}:
let
  pkgs = import nixpkgs { inherit system; };
  inherit (pkgs) lib;
  layer = import ./layer.nix { inherit lib pkgs; };

  cfg =
    (lib.evalModules {
      modules = [
        { options = import ./project-options.nix { inherit lib layer; }; }
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
      settings = lib.recursiveUpdate v.settings (
        {
          enabledPlugins = lib.mapAttrs' (n: _: lib.nameValuePair "${n}@sandbox" false) cfg.claude.lspServers;
        }
        // lib.optionalAttrs (cfg.guards.claudeApiKey.tokenCommand != null || claudeApiKey != "") {
          # As for a key from the user's config (module.nix): Claude Code
          # neither logs in nor asks about the key claude-api-proxy swaps in.
          apiKeyHelper = "echo sandbox-placeholder";
        }
      );
    };
in
layer.json.generate "sandbox-project.json" {
  inherit (cfg) hostPorts command;
  githubTokenCommand = cfg.guards.github.tokenCommand;
  claudeApiKeyCommand = cfg.guards.claudeApiKey.tokenCommand;
  gitFromHost = cfg.git.fromHost;
  gitSigningKey = cfg.git.signingKey;
  gitSigningKeyCommand = cfg.git.signingKeyCommand;
  forgejoTokenCommands = cfg.guards.forgejo.tokenCommands;
  wayland = {
    inherit (cfg.guards.wayland) enable globals;
  };
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
