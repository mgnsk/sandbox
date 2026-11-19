# What the top level, each profile and a project's sandbox.nix can set, and
# how a layer's Claude Code options become the managed config dir. Shared by
# module.nix and project.nix.
#
# Not packages or env: those are the top level's alone (module.nix). A
# project's tools and variables come from its dev shell (a flake, devenv),
# yours from your config, ~/.nix-profile or home-manager.
{ lib, pkgs }:
let
  inherit (lib) mkOption types;
  json = pkgs.formats.json { };

  bindType = types.submodule {
    options = {
      src = mkOption {
        type = types.str;
        description = "Host path. `~` and `$HOME`, `$USER`, `$XDG_RUNTIME_DIR` are expanded at start.";
      };
      dst = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Path inside; the same as src when null.";
      };
      mode = mkOption {
        type = types.enum [
          "ro"
          "rw"
        ];
        default = "ro";
      };
      optional = mkOption {
        type = types.bool;
        default = false;
        description = "Skip silently when src doesn't exist.";
      };
      hideGit = mkOption {
        type = types.bool;
        default = false;
        description = "Put an empty tmpfs over src/.git, so a repo bound for reference doesn't show its history. A bind of the project itself is skipped in favour of the project bind, read-write with .git.";
      };
    };
  };

  lspServerType = types.submodule (
    { config, name, ... }:
    {
      options = {
        package = mkOption {
          type = types.package;
          description = "The language server; its version is the plugin's, so a new one refreshes Claude Code's cached copy.";
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
        # Replaced by executable; kept only to say so.
        command = mkOption {
          type = types.nullOr types.anything;
          default = null;
          visible = false;
          apply =
            command:
            if command == null then
              null
            else
              throw "claude.lspServers.${name}.command is gone: the server is always a file in package, so set executable (its name in bin/) if it isn't the package's main program";
        };
        args = mkOption {
          type = types.listOf types.str;
          default = [ ];
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

  # The managed files' contents as nix values, from a layer's claude options
  # (already combined across layers). LSP servers become plugins of a
  # marketplace named lspMarketplace.
  claudeValues =
    {
      claude,
      lspMarketplace,
    }:
    let
      lsp = claude.lspServers;
      # Each server's executable: always a file in its package. Forcing
      # `command` reports a config that still sets it.
      lspExe = lib.mapAttrs (_: s: builtins.seq s.command "${s.package}/bin/${s.executable}") lsp;
      lspPlugins = lib.mapAttrsToList (n: s: {
        name = n;
        inherit (s.package) version;
        source = "./plugins/${n}";
        # No plugin.json: the marketplace entry is the whole manifest.
        strict = false;
        lspServers.${n} = {
          inherit (s) extensionToLanguage;
          command = lspExe.${n};
        }
        // lib.optionalAttrs (s.args != [ ]) { inherit (s) args; }
        // lib.optionalAttrs (s.settings != null) { inherit (s) settings; };
      }) lsp;
      lspDir = pkgs.runCommand "sandbox-claude-lsp-${lspMarketplace}" { } ''
        mkdir -p $out/.claude-plugin
        cp ${
          json.generate "marketplace.json" {
            name = lspMarketplace;
            description = "Language servers pinned by the sandbox configuration";
            owner.name = "sandbox";
            plugins = lspPlugins;
          }
        } $out/.claude-plugin/marketplace.json
        ${lib.concatStrings (
          lib.mapAttrsToList (n: exe: ''
            if [ ! -x ${lib.escapeShellArg exe} ]; then
              echo "claude.lspServers.${n}: no executable ${exe}" >&2
              exit 1
            fi
            mkdir -p $out/plugins/${n}
          '') lspExe
        )}
      '';
      marketplaces =
        lib.mapAttrs (_: p: {
          source = "directory";
          path = "${p}";
        }) claude.marketplaces
        // lib.optionalAttrs (lsp != { }) {
          ${lspMarketplace} = {
            source = "directory";
            path = "${lspDir}";
          };
        };
      marketplaceSettings = lib.optionalAttrs (marketplaces != { }) {
        env.CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL = 1;
        strictKnownMarketplaces = lib.attrValues marketplaces;
        extraKnownMarketplaces = lib.mapAttrs (_: source: {
          inherit source;
          autoUpdate = false;
        }) marketplaces;
        enabledPlugins = lib.genAttrs (map (n: "${n}@${lspMarketplace}") (lib.attrNames lsp)) (_: true);
      };
    in
    {
      settings = lib.recursiveUpdate marketplaceSettings claude.settings;
      inherit (claude) memory mcpServers;
      known = lib.mapAttrs (_: source: {
        inherit source;
        installLocation = source.path;
        lastUpdated = "1970-01-01T00:00:00.000Z";
      }) marketplaces;
    };
in
{
  inherit json;

  options = {
    binds = mkOption {
      type = types.listOf bindType;
      default = [ ];
      description = "Host paths bound in, after the per-project home volume (so they shadow it).";
    };
    claude = {
      settings = mkOption {
        inherit (json) type;
        default = { };
        description = "Claude Code managed-settings.json (merged across modules; outranks every other settings file).";
      };
      memory = mkOption {
        type = types.lines;
        default = "";
        description = "Managed CLAUDE.md every session loads.";
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
          Language servers, each an enabled plugin of a generated marketplace
          in the store (`sandbox`, or `project` for a project's sandbox.nix),
          so plugin and server are pinned together.
        '';
      };
      marketplaces = mkOption {
        type = types.attrsOf types.path;
        default = { };
        description = ''
          Plugin marketplaces: directories with a .claude-plugin/marketplace.json,
          e.g. store paths. Enable their plugins in `settings.enabledPlugins`.
          With any marketplace (or LSP server), Claude Code knows only these:
          it is registered before the first session, and other marketplaces
          (the official one, `/plugin marketplace add`) are refused.
        '';
      };
    };
  };

  inherit claudeValues;

  # The values of a managed config dir already in the store. Its strings
  # lose their context (fromJSON takes none), so whatever writes them out
  # must depend on dir itself to keep the paths in them alive.
  readClaudeDir =
    dir:
    let
      read =
        name: default:
        if builtins.pathExists "${dir}/${name}" then
          builtins.unsafeDiscardStringContext (builtins.readFile "${dir}/${name}")
        else
          default;
    in
    {
      settings = builtins.fromJSON (read "managed-settings.json" "{}");
      memory = read "CLAUDE.md" "";
      mcpServers = (builtins.fromJSON (read "managed-mcp.json" "{}")).mcpServers or { };
      known = builtins.fromJSON (read "known_marketplaces.json" "{}");
    };

  # top's values over base's: objects merged recursively, lists joined
  # (permission rules, hooks, allowed marketplaces add up), anything else
  # replaced.
  mergeClaudeValues =
    base: top:
    let
      merge =
        a: b:
        if builtins.isAttrs a && builtins.isAttrs b then
          a // lib.mapAttrs (n: v: if a ? ${n} then merge a.${n} v else v) b
        else if builtins.isList a && builtins.isList b then
          a ++ lib.filter (x: !(builtins.elem x a)) b
        else
          b;
    in
    {
      settings = merge base.settings top.settings;
      memory = lib.concatStringsSep "\n" (
        lib.filter (s: s != "") [
          base.memory
          top.memory
        ]
      );
      mcpServers = base.mcpServers // top.mcpServers;
      known = base.known // top.known;
    };

  claudeDir =
    name: values:
    {
      dependsOn ? [ ],
    }:
    pkgs.linkFarm "sandbox-claude-${name}" (
      lib.imap0 (i: path: {
        name = ".deps/${toString i}";
        inherit path;
      }) dependsOn
      ++ [
        {
          name = "managed-settings.json";
          path = json.generate "managed-settings.json" values.settings;
        }
        {
          name = "CLAUDE.md";
          path = pkgs.writeText "CLAUDE.md" values.memory;
        }
      ]
      ++ lib.optional (values.mcpServers != { }) {
        name = "managed-mcp.json";
        path = json.generate "managed-mcp.json" { inherit (values) mcpServers; };
      }
      # Claude Code registers a managed marketplace only partway through a
      # fresh volume's first session and installs nothing from it in that
      # one; listed already, every enabled plugin is installed at the first
      # start. sandbox-bin init links ~/.claude/plugins/known_marketplaces.json
      # here, read-only, so nothing Claude Code would add sticks.
      ++ lib.optional (values.known != { }) {
        name = "known_marketplaces.json";
        path = json.generate "known_marketplaces.json" values.known;
      }
    );
}
