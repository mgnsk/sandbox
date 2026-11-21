# A project's sandbox module as the manifest the launcher reads. Called by
# project.nix, and by the flake's check on a fixture.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;
  layer = import ./layer.nix { inherit lib pkgs; };

  cfg =
    (lib.evalModules {
      modules = [
        { options = import ./project-options.nix { inherit lib layer; }; }
        { _module.args.pkgs = lib.mkDefault pkgs; }
        module
      ];
    }).config;
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
}
