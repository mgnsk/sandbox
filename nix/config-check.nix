# The launcher's config from a fixture module, its fixed userland, and the
# options that are gone.
{
  evalSandbox,
  pkgs,
  runCommand,
  jq,
}:
let
  configFile = modules: (evalSandbox { inherit pkgs modules; }).configFile;
  config = configFile [ ./fixtures/settings.nix ];
  # Language servers: the package's main program, or another of its bin/.
  withLsp = configFile [
    {
      claude.lspServers.gopls = {
        package = pkgs.gopls;
        extensionToLanguage.".go" = "go";
      };
      claude.lspServers.json = {
        package = pkgs.vscode-langservers-extracted;
        executable = "vscode-json-language-server";
        args = [ "--stdio" ];
        extensionToLanguage.".json" = "json";
      };
    }
  ];
  fails = modules: !(builtins.tryEval (configFile modules).drvPath).success;
  lsp = server: {
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
    package = pkgs.gopls;
    command = "gopls";
  })
];
assert fails [
  (lsp {
    package = pkgs.gopls;
    executable = "../../gopls";
  })
];
assert fails [ (lsp { package = pkgs.vscode-langservers-extracted; }) ];
# No configuration adds tools.
assert fails [ { packages = [ pkgs.hello ]; } ];
assert fails [ { basePackages = [ ]; } ];
assert fails [ { claude.package = pkgs.hello; } ];
runCommand "sandbox-config-check" { nativeBuildInputs = [ jq ]; } ''
  jq -e '
    .guards.forgejo == true
    and .hostPorts == ["5432"]
    and .default.env.EDITOR == "nvim"
    and .default.claudeApiKeyCommand == null
    and ([.profiles[] | {name, paths, claudeApiKeyCommand}]
         == [{name: "work", paths: ["~/work"], claudeApiKeyCommand: "op read op://v/claude/key"}])
  ' ${config}
  bin=$(jq -r '.default.env.PATH | split(":")[0]' ${config})
  for tool in bash nix sed make tic xdg-open; do test -x "$bin/$tool"; done
  for tool in claude git curl python3 hello; do test ! -e "$bin/$tool"; done
  test -f "$(jq -r '.default.claudeDir' ${config})/managed-settings.json"
  settings="$(jq -r '.default.claudeDir' ${withLsp})/managed-settings.json"
  jq -e \
    --arg gopls ${pkgs.gopls}/bin/gopls \
    --arg json ${pkgs.vscode-langservers-extracted}/bin/vscode-json-language-server '
    (.plugins | map({key: .name, value: .lspServers[.name].command}) | from_entries)
      == {gopls: $gopls, json: $json}
  ' "$(jq -r '.extraKnownMarketplaces.sandbox.source.path' "$settings")/.claude-plugin/marketplace.json"
  touch $out
''
