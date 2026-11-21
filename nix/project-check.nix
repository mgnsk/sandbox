# manifest.nix on a fixture sandbox module, sandbox.lib.mkShell's contract
# with project.nix (the module on the shell, with its default command), and
# sandbox.lib.mkClaude's wrapper run against a stand-in claude.
{
  lib,
  pkgs,
  runCommand,
  writeShellScriptBin,
  jq,
  gopls,
  vscode-langservers-extracted,
}:
let
  sandboxLib = import ./lib.nix { inherit lib; };
  manifest = module: import ./manifest.nix { inherit pkgs module; };

  fixture = manifest ./fixtures/project.nix;
  shell = sandboxLib.mkShell {
    inherit pkgs;
    sandbox.hostPorts = [ "1" ];
    claude.package = fakeClaude;
    CGO_ENABLED = "0";
  };
  # The flake's own command over mkShell's default.
  ownCommand = sandboxLib.mkShell {
    inherit pkgs;
    sandbox.command = [ "make" ];
  };

  # Prints what it was run with.
  fakeClaude = writeShellScriptBin "claude" ''
    echo "CLAUDE_CONFIG_DIR=$CLAUDE_CONFIG_DIR"
    printf '%s\n' "$@"
  '';
  claude = sandboxLib.mkClaude {
    inherit pkgs;
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
  fails = f: !(builtins.tryEval (f { }).drvPath).success;
  lsp =
    server:
    sandboxLib.mkClaude {
      inherit pkgs;
      package = fakeClaude;
      lspServers.x = {
        extensionToLanguage.".x" = "x";
      }
      // server;
    };
in
# No free-form command; no executable outside bin/; a package without a
# main program needs executable.
assert fails (
  _:
  lsp {
    package = gopls;
    command = "gopls";
  }
);
assert fails (
  _:
  lsp {
    package = gopls;
    executable = "../../gopls";
  }
);
assert fails (_: lsp { package = vscode-langservers-extracted; });
assert shell.CGO_ENABLED == "0";
assert lib.any (p: lib.getName p == "claude-code-sandbox") shell.nativeBuildInputs;
runCommand "sandbox-project-check" { nativeBuildInputs = [ jq ]; } ''
  jq -e '
    .hostPorts == ["5432"]
    and .command == ["nix", "develop"]
    and .binds == [{src: "~/data", dst: null, mode: "rw", optional: false, hideGit: false}]
    and .githubTokenCommand == "op read op://v/gh/token"
    and .forgejoTokenCommands == {"codeberg.org": "op read op://v/cb/token"}
    and .claudeApiKeyCommand == "op read op://v/claude/key"
    and .gitFromHost == true
    and .gitSigningKey == null
    and .gitSigningKeyCommand == "op read op://v/ssh/public-key"
    and .wayland == {enable: true, globals: {wl_data_device_manager: true, wl_drm: false}}
  ' ${fixture}
  jq -e '.hostPorts == ["1"] and .command == ["nix", "develop"]' ${manifest shell.sandbox}
  jq -e '.command == ["make"]' ${manifest ownCommand.sandbox}

  export HOME=$TMPDIR/home XDG_RUNTIME_DIR=$TMPDIR/run
  ran=$(${lib.getExe claude} -p hi)
  echo "$ran"
  arg() { grep -A1 -x -- "$1" <<<"$ran" | sed -n 2p; }
  grep -qx "CLAUDE_CONFIG_DIR=$HOME/.claude-project" <<<"$ran"
  test "$(tail -2 <<<"$ran")" = "$(printf -- '-p\nhi')"
  grep -qx -- --strict-mcp-config <<<"$ran"
  jq -e '.mcpServers.x.command == "x"' "$(arg --mcp-config)"
  settings=$(arg --settings)
  jq -e '
    .permissions.allow == ["Bash(go test:*)"]
    and .env.DISABLE_AUTOUPDATER == 1
    and (.hooks.PreToolUse[0].hooks | length) == 2
    and has("apiKeyHelper") == false
  ' "$settings"
  for hook in $(jq -r '.hooks.PreToolUse[0].hooks[].command' "$settings"); do test -x "$hook"; done
  grep -qx 'project memory' "$(arg --append-system-prompt-file)"
  plugin=$(arg --plugin-dir)
  jq -e '.name == "lsp"' "$plugin/.claude-plugin/plugin.json"
  jq -e --arg gopls ${gopls}/bin/gopls \
    --arg json ${vscode-langservers-extracted}/bin/vscode-json-language-server '
    .gopls == {command: $gopls, extensionToLanguage: {".go": "go"}}
    and .json == {command: $json, args: ["--stdio"], extensionToLanguage: {".json": "json"}}
  ' "$plugin/.lsp.json"

  # On the Claude API guard: the placeholder key.
  ran=$(ANTHROPIC_UNIX_SOCKET=/s ${lib.getExe claude})
  jq -e '.apiKeyHelper == "echo sandbox-placeholder"' "$(arg --settings)"
  # remote-control refuses the session flags.
  test "$(${lib.getExe claude} rc --x)" = "$(printf 'CLAUDE_CONFIG_DIR=%s\nrc\n--x' "$HOME/.claude-project")"
  touch $out
''
