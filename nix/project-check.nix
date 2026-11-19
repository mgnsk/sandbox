# project.nix on a fixture sandbox.nix, and the merge of a project's Claude
# config over a profile's.
{
  lib,
  pkgs,
  runCommand,
  jq,
}:
let
  layer = import ./layer.nix { inherit lib pkgs; };
  manifest = import ./project.nix {
    nixpkgs = pkgs.path;
    inherit (pkgs.stdenv.hostPlatform) system;
    file = ./fixtures/sandbox.nix;
  };
  merged =
    layer.mergeClaudeValues
      {
        settings = {
          permissions.allow = [ "a" ];
          enabledPlugins."gopls@sandbox" = true;
          theme = "dark";
        };
        memory = "base";
        mcpServers.a = { };
        known.sandbox = { };
      }
      {
        settings = {
          permissions.allow = [
            "a"
            "b"
          ];
          enabledPlugins."gopls@sandbox" = false;
          theme = "light";
        };
        memory = "";
        mcpServers.b = { };
        known.project = { };
      };
in
assert
  merged.settings == {
    permissions.allow = [
      "a"
      "b"
    ];
    enabledPlugins."gopls@sandbox" = false;
    theme = "light";
  };
assert merged.memory == "base";
assert
  lib.attrNames merged.mcpServers == [
    "a"
    "b"
  ];
assert
  lib.attrNames merged.known == [
    "project"
    "sandbox"
  ];
runCommand "sandbox-project-check" { nativeBuildInputs = [ jq ]; } ''
  jq -e '
    .hostPorts == ["5432"]
    and .command == ["nix", "develop"]
    and .claudeDir == null
    and .binds == [{src: "~/data", dst: null, mode: "rw", optional: false, hideGit: false}]
    and .githubTokenCommand == "op read op://v/gh/token"
    and .forgejoTokenCommands == {"codeberg.org": "op read op://v/cb/token"}
    and .claudeApiKeyCommand == "op read op://v/claude/key"
  ' ${manifest}
  touch $out
''
