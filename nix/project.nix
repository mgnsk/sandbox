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
            git.fromHost = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Take git's name, email and ssh signing key inside from each
                user's global git config on the host (`git config --global`,
                run from /), where nothing more specific sets them. A user's
                .sandbox.yml can turn it off (git.fromHost: false).
              '';
            };
            git.signingKey = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "ssh-ed25519 AAAA...";
              description = "An ssh public key in the user's agent: git inside signs commits and tags with it. A user's .sandbox.yml wins.";
            };
            git.signingKeyCommand = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "op read \"op://Employee/GitHub SSH key/public key\"";
              description = ''
                A shell command printing that public key, run on the host at
                each start once the user approves it, like the token
                commands. A user's .sandbox.yml wins.
              '';
            };
            guards.claudeApiKey.tokenCommand = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "A shell command printing a Claude API key for Claude Code inside, approved like guards.github.tokenCommand.";
            };
            guards.wayland.enable = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Windows on the host's Wayland display, for GUI programs
                inside, through a proxy that passes on only an allowlist of
                the compositor's globals. Takes the user's yes on the
                terminal (asked once, and again whenever it changes); their
                own config can turn it on or off for every project.
              '';
            };
            guards.wayland.globals = lib.mkOption {
              type = lib.types.attrsOf lib.types.bool;
              default = { };
              example = {
                wl_data_device_manager = true;
              };
              description = ''
                Changes to the allowlist of Wayland globals, by interface
                name: true adds one to the default list, which takes the
                user's yes like enable; false removes one. The user's own
                changes go over these.
              '';
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
