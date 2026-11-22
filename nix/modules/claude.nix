# claude.*: Claude Code in the sandbox, with managed config at
# /etc/claude-code - settings, memory and MCP servers that outrank every
# settings file in ~/.claude, which the sandbox can write.
#
# `claude` is a wrapper around claude-code that adds what managed config
# can't carry: the language servers and plugins (--plugin-dir), and the
# placeholder key when the Claude API guard runs (--settings with an
# apiKeyHelper, which the managed settings leave out so that a login inside
# works without the guard).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.claude;
  json = pkgs.formats.json { };

  lspServerType = types.submodule (
    { config, name, ... }:
    {
      options = {
        package = mkOption {
          type = types.package;
          description = "The language server.";
        };
        executable = mkOption {
          type = types.strMatching "[^/]+";
          default =
            config.package.meta.mainProgram
              or (throw "claude.lspServers.${name}: ${config.package.name} has no meta.mainProgram; set executable to the server's name in its bin/");
          defaultText = lib.literalExpression "package.meta.mainProgram";
          example = "vscode-json-language-server";
          description = ''
            The server's name in the package's bin/, for a package whose main
            program isn't the server. The server is always that file in
            `package`: never a command looked up on PATH.
          '';
        };
        args = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "--stdio" ];
          description = "Arguments the server is started with.";
        };
        extensionToLanguage = mkOption {
          type = types.attrsOf types.str;
          example = {
            ".go" = "go";
          };
          description = "File extensions the server handles, with their LSP language ids.";
        };
        settings = mkOption {
          type = types.nullOr json.type;
          default = null;
          description = "Server settings (workspace/configuration).";
        };
      };
    }
  );

  hook =
    name:
    lib.getExe (
      pkgs.writeShellApplication {
        inherit name;
        runtimeInputs = [
          pkgs.jq
          pkgs.gnugrep
          pkgs.gnused
        ];
        text = builtins.readFile ./claude-hooks/${name}.sh;
      }
    );

  claude = lib.getExe cfg.package;

  # With the Claude API guard (guards.claudeApiKey): a placeholder, so
  # Claude Code neither asks to log in nor to approve an environment key;
  # claude-api-proxy swaps in the real one.
  keySettings = json.generate "claude-settings-key.json" {
    apiKeyHelper = "echo sandbox-placeholder";
  };

  lspExe = lib.mapAttrs (_: s: "${s.package}/bin/${s.executable}") cfg.lspServers;
  lspPlugin = pkgs.runCommand "claude-lsp-plugin" { } ''
    mkdir -p $out/.claude-plugin
    cp ${json.generate "plugin.json" { name = "lsp"; }} $out/.claude-plugin/plugin.json
    cp ${
      json.generate "lsp.json" (
        lib.mapAttrs (
          n: s:
          {
            command = lspExe.${n};
            inherit (s) extensionToLanguage;
          }
          // lib.optionalAttrs (s.args != [ ]) { inherit (s) args; }
          // lib.optionalAttrs (s.settings != null) { inherit (s) settings; }
        ) cfg.lspServers
      )
    } $out/.lsp.json
    ${lib.concatStrings (
      lib.mapAttrsToList (n: exe: ''
        if [ ! -x ${lib.escapeShellArg exe} ]; then
          echo "claude.lspServers.${n}: no executable ${exe}" >&2
          exit 1
        fi
      '') lspExe
    )}
  '';
  plugins = lib.optional (cfg.lspServers != { }) lspPlugin ++ cfg.plugins;
  pluginArgs = lib.concatMap (p: [
    "--plugin-dir"
    "${p}"
  ]) plugins;

  wrapper = pkgs.writeTextFile {
    name = "claude-code-sandbox";
    destination = "/bin/claude";
    executable = true;
    meta.mainProgram = "claude";
    checkPhase = "${pkgs.stdenv.shellDryRun} $target";
    text = ''
      #!${pkgs.runtimeShell}
      case "''${1-}" in
      # Refuses session flags before the verb (they'd not reach the
      # sessions it starts): its own options come after it.
      rc | remote-control) exec -a "$0" ${claude} "$@" ;;
      esac
      set -- ${lib.escapeShellArgs pluginArgs} "$@"
      if [ -n "''${ANTHROPIC_UNIX_SOCKET-}" ]; then
        set -- --settings ${keySettings} "$@"
      fi
      exec -a "$0" ${claude} "$@"
    '';
  };
in
{
  options.claude = {
    enable = lib.mkEnableOption "Claude Code in the sandbox, as `claude`, with managed config at /etc/claude-code";
    package = mkOption {
      type = types.package;
      default = pkgs.claude-code;
      defaultText = lib.literalExpression "pkgs.claude-code";
      description = "The Claude Code that's wrapped (unfree: the pkgs given must allow it).";
    };
    settings = mkOption {
      inherit (json) type;
      default = { };
      description = ''
        Managed settings (/etc/claude-code/managed-settings.json): over every
        other settings file. Merged across modules.
      '';
    };
    memory = mkOption {
      type = types.lines;
      default = "";
      description = "The managed CLAUDE.md every session loads, after the sandbox's AGENTS.md (`agentsMd`).";
    };
    mcpServers = mkOption {
      type = types.attrsOf json.type;
      default = { };
      description = ''
        Managed MCP servers. Managed MCP config is exclusive: once any is
        set, a project's own .mcp.json is ignored.
      '';
    };
    lspServers = mkOption {
      type = types.attrsOf lspServerType;
      default = { };
      description = ''
        Language servers, in a plugin of their own (--plugin-dir) that runs
        each from its store path, so plugin and server are pinned together.
      '';
    };
    plugins = mkOption {
      type = types.listOf types.path;
      default = [ ];
      description = "Plugin directories (with a .claude-plugin/plugin.json), each given with --plugin-dir.";
    };
  };

  config = lib.mkIf cfg.enable {
    packages = [ wrapper ];

    claude.settings = lib.mkMerge [
      {
        # A store path can't update itself.
        env.DISABLE_AUTOUPDATER = 1;
      }
      {
        hooks.PreToolUse = [
          {
            matcher = "Bash";
            hooks = [
              {
                type = "command";
                command = hook "deny-github-http";
              }
              {
                type = "command";
                command = hook "deny-cli-login";
              }
            ];
          }
        ];
      }
    ];

    etc = {
      "claude-code/managed-settings.json".source = json.generate "managed-settings.json" cfg.settings;
      "claude-code/CLAUDE.md".text = lib.concatStringsSep "\n" (
        lib.filter (s: s != "") [
          config.agentsMd
          cfg.memory
        ]
      );
    }
    // lib.optionalAttrs (cfg.mcpServers != { }) {
      "claude-code/managed-mcp.json".source = json.generate "managed-mcp.json" {
        inherit (cfg) mcpServers;
      };
    };
  };
}
