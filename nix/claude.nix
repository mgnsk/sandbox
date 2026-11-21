# sandbox.lib.mkClaude: Claude Code for a project's dev shell, configured
# by the project's flake rather than by the sandbox. A wrapper around
# claude-code that
#
# - keeps its own config dir (configDir), so a claude of the user's own -
#   home-manager's ~/.claude, linked into every sandbox - doesn't apply;
# - passes settings, MCP servers, language servers and plugins as flags,
#   which outrank every settings file in that dir;
# - appends the running sandbox's /etc/sandbox/AGENTS.md and memory to the
#   system prompt;
# - takes the placeholder key when the sandbox runs the Claude API guard.
#
#   sandbox.lib.mkClaude { inherit pkgs; settings = { ... }; ... }
#
# Everything but pkgs is a module of the options below (OPTIONS.md).
{ lib }:
let
  inherit (lib) mkOption types;

  module =
    {
      config,
      pkgs,
      ...
    }:
    let
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
                  or (throw "lspServers.${name}: ${config.package.name} has no meta.mainProgram; set executable to the server's name in its bin/");
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
            text = builtins.readFile ./claude/${name}.sh;
          }
        );
    in
    {
      options = {
        package = mkOption {
          type = types.package;
          default = pkgs.claude-code;
          defaultText = lib.literalExpression "pkgs.claude-code";
          description = "The Claude Code that's wrapped (unfree: the pkgs given must allow it).";
        };
        configDir = mkOption {
          type = types.nullOr types.str;
          default = "$HOME/.claude-project";
          description = ''
            CLAUDE_CONFIG_DIR: its login, history and state, and the
            user-level settings, memory, skills and plugins it reads -
            none of them a claude of your own's (home-manager's ~/.claude).
            Expanded by the shell at each start. null leaves it to the
            environment.
          '';
        };
        settings = mkOption {
          inherit (json) type;
          default = { };
          description = ''
            Settings, given with --settings: over every settings file but
            managed ones. Merged across modules.
          '';
        };
        memory = mkOption {
          type = types.lines;
          default = "";
          description = "Appended to the system prompt, after the sandbox's AGENTS.md.";
        };
        mcpServers = mkOption {
          type = types.attrsOf json.type;
          default = { };
          description = ''
            MCP servers, given with --mcp-config. With any, they're the only
            ones (--strict-mcp-config): a .mcp.json in the project is
            ignored.
          '';
        };
        lspServers = mkOption {
          type = types.attrsOf lspServerType;
          default = { };
          description = ''
            Language servers, in a plugin of their own (--plugin-dir) that
            runs each from its store path, so plugin and server are pinned
            together.
          '';
        };
        plugins = mkOption {
          type = types.listOf types.path;
          default = [ ];
          description = "Plugin directories (with a .claude-plugin/plugin.json), each given with --plugin-dir.";
        };
        finalPackage = mkOption {
          type = types.package;
          readOnly = true;
          internal = true;
        };
      };

      config = {
        settings = lib.mkMerge [
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

        finalPackage =
          let
            cfg = config;
            claude = lib.getExe cfg.package;
            settings = json.generate "claude-settings.json" cfg.settings;
            # With the Claude API guard (guards.claudeApiKey): a placeholder,
            # so Claude Code neither asks to log in nor to approve an
            # environment key; claude-api-proxy swaps in the real one.
            keySettings = json.generate "claude-settings-key.json" (
              { apiKeyHelper = "echo sandbox-placeholder"; } // cfg.settings
            );
            mcp = json.generate "claude-mcp.json" { inherit (cfg) mcpServers; };
            memory = pkgs.writeText "claude-memory.md" cfg.memory;

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
                    echo "lspServers.${n}: no executable ${exe}" >&2
                    exit 1
                  fi
                '') lspExe
              )}
            '';
            plugins = lib.optional (cfg.lspServers != { }) lspPlugin ++ cfg.plugins;

            args =
              lib.optionals (cfg.mcpServers != { }) [
                "--mcp-config"
                "${mcp}"
                "--strict-mcp-config"
              ]
              ++ lib.concatMap (p: [
                "--plugin-dir"
                "${p}"
              ]) plugins;
          in
          pkgs.writeTextFile {
            name = "claude-code-sandbox";
            destination = "/bin/claude";
            executable = true;
            meta.mainProgram = "claude";
            checkPhase = "${pkgs.stdenv.shellDryRun} $target";
            text = ''
              #!${pkgs.runtimeShell}
              set -eu
              ${lib.optionalString (cfg.configDir != null) ''
                export CLAUDE_CONFIG_DIR="${cfg.configDir}"
              ''}
              case "''${1-}" in
              # Refuses session flags before the verb (they'd not reach the
              # sessions it starts): its own options come after it.
              rc | remote-control) exec -a "$0" ${claude} "$@" ;;
              esac

              settings=${settings}
              if [ -n "''${ANTHROPIC_UNIX_SOCKET-}" ]; then
                settings=${keySettings}
              fi

              # The running sandbox's AGENTS.md - what it is, which guards
              # run - then the project's memory, written where only this
              # sandbox sees it.
              dir="''${XDG_RUNTIME_DIR:-/tmp}/sandbox-claude"
              mkdir -p "$dir"
              {
                if [ -r /etc/sandbox/AGENTS.md ]; then
                  cat /etc/sandbox/AGENTS.md
                  echo
                fi
                cat ${memory}
              } >"$dir/prompt.md.$$"
              # Whole for a session starting next to this one.
              mv -f "$dir/prompt.md.$$" "$dir/prompt.md"

              exec -a "$0" ${claude} --settings "$settings" \
                --append-system-prompt-file "$dir/prompt.md" \
                ${lib.escapeShellArgs args} "$@"
            '';
          };
      };
    };
in
{
  inherit module;

  mkClaude =
    { pkgs, ... }@args:
    (lib.evalModules {
      modules = [
        module
        { _module.args.pkgs = lib.mkDefault pkgs; }
        (removeAttrs args [ "pkgs" ])
      ];
    }).config.finalPackage;
}
