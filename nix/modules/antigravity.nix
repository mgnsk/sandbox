# antigravity.*: Google's Antigravity CLI in the sandbox, as `agy`.
#
# agy has no managed config to outrank ~/.gemini, which the sandbox can
# write: what Claude Code gets from /etc/claude-code comes here from the
# wrapper. Each run it
# - links the sandbox's plugin (its rules, hooks and MCP servers) and the
#   configured plugins into ~/.gemini/config/plugins, next to the user's
#   own, and removes links of plugins no longer configured;
# - passes the settings with --settings, which go over
#   ~/.gemini/antigravity-cli/settings.json for that run and are never
#   saved;
# - turns the auto-updater off (a store path can't update itself).
# Its own sandbox for commands (enableTerminalSandbox) is off by default:
# it needs nested namespaces, which the sandbox blocks.
# So they're pinned defaults, not enforced: anything inside can replace a
# link or disable the plugin until the next run. Only admin_settings.json,
# at /etc/antigravity, is out of the sandbox's reach.
#
# TODO: a Gemini API key guard like guards.claudeApiKey; until then agy
# logs in inside. Either agy takes modelProvider "gemini" with
# GEMINI_API_KEY and GOOGLE_GEMINI_BASE_URL, or gateway mode in
# admin_settings.json (gateway.enabled, gateway.url at the router,
# AGY_LLM_GATEWAY_API_KEY a placeholder) sends all model traffic there,
# without a Google sign-in; either way a host proxy adds the real key. Never
# gateway.apiKey: /etc is readable inside. Drop this once that guard exists.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.antigravity;
  json = pkgs.formats.json { };

  hook = import ./agent-hooks.nix { inherit lib pkgs; } "antigravity";

  rules = lib.concatStringsSep "\n" (
    lib.filter (s: s != "") [
      config.agentsMd
      cfg.rules
    ]
  );

  # The sandbox's own plugin: a plugin's rules, hooks and MCP servers are
  # additions, so the user's own in ~/.gemini/config stay theirs.
  plugin = pkgs.runCommand "antigravity-sandbox-plugin" { } ''
    mkdir -p $out/rules
    cp ${json.generate "plugin.json" { name = "sandbox"; }} $out/plugin.json
    cp ${pkgs.writeText "AGENTS.md" rules} $out/rules/AGENTS.md
    cp ${
      json.generate "hooks.json" {
        sandbox.PreToolUse = [
          {
            matcher = "run_command";
            hooks = [
              { command = hook "deny-github-http"; }
              { command = hook "deny-cli-login"; }
            ];
          }
        ];
      }
    } $out/hooks.json
    ${lib.optionalString (cfg.mcpServers != { }) ''
      cp ${json.generate "mcp_config.json" { inherit (cfg) mcpServers; }} $out/mcp_config.json
    ''}
  '';

  # Link names in ~/.gemini/config/plugins: the wrapper owns `sandbox` and
  # `sandbox-*` links into the store.
  links = {
    sandbox = plugin;
  }
  // lib.mapAttrs' (n: p: lib.nameValuePair "sandbox-${n}" p) cfg.plugins;

  settingsFile = json.generate "antigravity-settings.json" cfg.settings;

  wrapper = pkgs.writeTextFile {
    name = "antigravity-cli-sandbox";
    destination = "/bin/agy";
    executable = true;
    meta.mainProgram = "agy";
    checkPhase = "${pkgs.stdenv.shellDryRun} $target";
    text = ''
      #!${pkgs.runtimeShell}
      dir=''${HOME:?}/.gemini/config/plugins
      ${lib.getExe' pkgs.coreutils "mkdir"} -p "$dir"
      for link in "$dir"/sandbox "$dir"/sandbox-*; do
        [ -L "$link" ] || continue
        case $(${lib.getExe' pkgs.coreutils "readlink"} "$link") in
        ${builtins.storeDir}/*) ;;
        *) continue ;;
        esac
        case "''${link##*/}" in
        ${lib.concatMapStringsSep " | " lib.escapeShellArg (lib.attrNames links)}) ;;
        *) ${lib.getExe' pkgs.coreutils "rm"} -f "$link" ;;
        esac
      done
      ${lib.concatStrings (
        lib.mapAttrsToList (
          n: p:
          let
            name = lib.escapeShellArg n;
          in
          ''
            if [ "$(${lib.getExe' pkgs.coreutils "readlink"} "$dir"/${name})" != ${p} ]; then
              ${lib.getExe' pkgs.coreutils "ln"} -sfnT ${p} "$dir"/${name} ||
                echo "agy: not linking ~/.gemini/config/plugins/"${name} >&2
            fi
          ''
        ) links
      )}
      export AGY_CLI_DISABLE_AUTO_UPDATE=1
      ${lib.optionalString (cfg.settings != { }) "set -- --settings ${settingsFile} \"$@\""}
      exec -a "$0" ${lib.getExe cfg.package} "$@"
    '';
  };
in
{
  options.antigravity = {
    enable = lib.mkEnableOption "the Antigravity CLI in the sandbox, as `agy`, with the sandbox's rules, hooks and MCP servers in a plugin of its own";
    package = mkOption {
      type = types.package;
      default = pkgs.antigravity-cli;
      defaultText = lib.literalExpression "pkgs.antigravity-cli";
      description = "The Antigravity CLI that's wrapped (unfree: the pkgs given must allow it).";
    };
    settings = mkOption {
      inherit (json) type;
      default = { };
      example = {
        agentMode = "accept-edits";
      };
      description = ''
        Settings given with --settings at every run: over
        ~/.gemini/antigravity-cli/settings.json, for that run only, never
        saved. Merged across modules. `enableTerminalSandbox` defaults to
        false: agy's own sandbox for commands needs nested namespaces, which
        the sandbox blocks, so each command would fail there before agy
        retried it outside.
      '';
    };
    rules = mkOption {
      type = types.lines;
      default = "";
      description = "Rules every session loads, after the sandbox's AGENTS.md (`agentsMd`): the sandbox plugin's rules/AGENTS.md.";
    };
    mcpServers = mkOption {
      type = types.attrsOf json.type;
      default = { };
      example = lib.literalExpression "{ mcp-nixos.command = lib.getExe pkgs.mcp-nixos; }";
      description = ''
        MCP servers (mcp_config.json's `mcpServers`), in the sandbox plugin:
        added to the user's and the project's own.
      '';
    };
    plugins = mkOption {
      type = types.attrsOf types.path;
      default = { };
      example = lib.literalExpression "{ team = ./antigravity-plugin; }";
      description = ''
        Plugin directories (with a plugin.json), each linked at
        ~/.gemini/config/plugins/sandbox-<name>.
      '';
    };
    adminSettings = mkOption {
      inherit (json) type;
      default = { };
      description = ''
        /etc/antigravity/admin_settings.json, agy's enterprise policy
        (models, MCP, permissions, the LLM gateway): the one part of its
        config the sandbox can't write. Not written when empty.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    antigravity.settings.enableTerminalSandbox = lib.mkDefault false;
    packages = [ wrapper ];
    etc = lib.optionalAttrs (cfg.adminSettings != { }) {
      "antigravity/admin_settings.json".source = json.generate "admin_settings.json" cfg.adminSettings;
    };
  };
}
