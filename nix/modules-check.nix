# claude.* and vscode.*: what they put in the configuration (packages,
# /etc files, the Wayland guard), and the claude wrapper run against a
# stand-in claude-code.
{
  evalSandbox,
  lib,
  pkgs,
  runCommand,
  writeShellScriptBin,
  jq,
  gopls,
  vscode-langservers-extracted,
}:
let
  # Prints what it was run with.
  fakeClaude = writeShellScriptBin "claude" ''printf '%s\n' "$@"'';
  fakeCode = writeShellScriptBin "code" ''printf '%s\n' "$@"'';
  eval = modules: evalSandbox { inherit pkgs modules; };
  cfg = eval [
    {
      agentsMd = "Company notes.";
      claude = {
        enable = true;
        package = fakeClaude;
        memory = "project memory";
        settings.permissions.allow = [ "Bash(go test:*)" ];
        mcpServers.x = {
          type = "stdio";
          command = "x";
        };
        lspServers.gopls = {
          package = gopls;
          extensionToLanguage.".go" = "go";
        };
        lspServers.json = {
          package = vscode-langservers-extracted;
          executable = "vscode-json-language-server";
          args = [ "--stdio" ];
          extensionToLanguage.".json" = "json";
        };
      };
      vscode = {
        enable = true;
        package = fakeCode;
      };
      etc."x/y".text = "z";
    }
  ];
  off = eval [ ];
  claude = lib.findFirst (p: lib.getName p == "claude-code-sandbox") null cfg.packages;
  code = lib.findFirst (p: lib.getName p == "code") null cfg.packages;
  etc = lib.mapAttrs (_: f: f.source) cfg.etc;
  fails = modules: !(builtins.tryEval (eval modules).configFile.drvPath).success;
  lsp = server: {
    claude.enable = true;
    claude.package = fakeClaude;
    claude.lspServers.x = {
      extensionToLanguage.".x" = "x";
    }
    // server;
  };
in
# No free-form command; no executable outside bin/; a package without a
# main program needs executable.
assert fails [
  (lsp {
    package = gopls;
    command = "gopls";
  })
];
assert fails [
  (lsp {
    package = gopls;
    executable = "../../gopls";
  })
];
assert fails [ (lsp { package = vscode-langservers-extracted; }) ];
assert claude != null && code != null;
assert cfg.guards.wayland.enable;
assert !off.guards.wayland.enable && off.packages == [ ];
# Without them, /etc has only AGENTS.md.
assert lib.attrNames off.etc == [ "sandbox/AGENTS.md" ];
runCommand "sandbox-modules-check" { nativeBuildInputs = [ jq ]; } ''
  # The /etc files.
  test "$(cat ${etc."x/y"})" = z
  grep -q '^# Sandbox' ${etc."sandbox/AGENTS.md"}
  grep -q 'Company notes.' ${etc."sandbox/AGENTS.md"}
  grep -q '^# Sandbox' ${etc."claude-code/CLAUDE.md"}
  tail -1 ${etc."claude-code/CLAUDE.md"} | grep -qx 'project memory'
  jq -e '.mcpServers.x.command == "x"' ${etc."claude-code/managed-mcp.json"}
  settings=${etc."claude-code/managed-settings.json"}
  jq -e '
    .permissions.allow == ["Bash(go test:*)"]
    and .env.DISABLE_AUTOUPDATER == 1
    and (.hooks.PreToolUse[0].hooks | length) == 2
    and has("apiKeyHelper") == false
  ' $settings
  for hook in $(jq -r '.hooks.PreToolUse[0].hooks[].command' $settings); do test -x "$hook"; done

  # The wrapper: language servers as a plugin, the placeholder key only on
  # the Claude API guard.
  ran=$(${lib.getExe claude} -p hi)
  echo "$ran"
  arg() { grep -A1 -x -- "$1" <<<"$ran" | sed -n 2p; }
  test "$(tail -2 <<<"$ran")" = "$(printf -- '-p\nhi')"
  ! grep -qx -- --settings <<<"$ran"
  plugin=$(arg --plugin-dir)
  jq -e '.name == "lsp"' "$plugin/.claude-plugin/plugin.json"
  jq -e --arg gopls ${gopls}/bin/gopls \
    --arg json ${vscode-langservers-extracted}/bin/vscode-json-language-server '
    .gopls == {command: $gopls, extensionToLanguage: {".go": "go"}}
    and .json == {command: $json, args: ["--stdio"], extensionToLanguage: {".json": "json"}}
  ' "$plugin/.lsp.json"
  ran=$(ANTHROPIC_UNIX_SOCKET=/s ${lib.getExe claude})
  jq -e '.apiKeyHelper == "echo sandbox-placeholder"' "$(arg --settings)"
  # remote-control refuses the session flags.
  test "$(${lib.getExe claude} rc --x)" = "$(printf 'rc\n--x')"

  # code: on a Wayland display only, with Chromium's sandbox off.
  ! ${lib.getExe code} 2>/dev/null
  ran=$(WAYLAND_DISPLAY=wayland-0 ${lib.getExe code} .)
  grep -qx -- --no-sandbox <<<"$ran"
  grep -qx -- --ozone-platform=wayland <<<"$ran"
  test "$(tail -1 <<<"$ran")" = .
  touch $out
''
