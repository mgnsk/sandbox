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
assert fails [ { env.EDITOR = "nvim"; } ];
# The API guards have no switch.
assert fails [ { guards.github.enable = false; } ];
assert fails [ { guards.forgejo.enable = true; } ];
runCommand "sandbox-config-check" { nativeBuildInputs = [ jq ]; } ''
  jq -e '
    .hostPorts == ["5432"]
    and .guards.notifications == true
    and .guards.wayland.enable == null
    and .guards.wayland.globals == {zwp_tablet_manager_v2: false}
    and (.guards.wayland.defaultGlobals | index("xdg_wm_base") != null)
    and (.guards.wayland.defaultGlobals | index("wl_data_device_manager") == null)
    and .default.claudeApiKeyCommand == null
    and ([.profiles[] | {name, paths, claudeApiKeyCommand}]
         == [{name: "work", paths: ["~/work"], claudeApiKeyCommand: "op read op://v/claude/key"}])
  ' ${config}
  bin=$(jq -r '.default.env.PATH | split(":")[0]' ${config})
  for tool in bash nix sed make tic git less nano ssh ssh-keygen xdg-open \
    jq curl rg which ps unzip zip; do test -x "$bin/$tool"; done
  for tool in claude python3 hello; do test ! -e "$bin/$tool"; done
  grep -q EDITOR "$(jq -r '.fhs.profile' ${config})"
  test -x "$(jq -r '.tools.wlVeil' ${config})"
  test -f "$(jq -r '.default.claudeDir' ${config})/managed-settings.json"
  test -f "$(jq -r '.fhs.bashCompletion' ${config})/bash_completion"
  grep -q bash_completion "$(jq -r '.fhs.bashrc' ${config})"
  grep -q PS1= "$(jq -r '.fhs.bashrc' ${config})"
  grep -q /etc/bashrc "$(jq -r '.fhs.profile' ${config})"
  settings="$(jq -r '.default.claudeDir' ${withLsp})/managed-settings.json"
  jq -e \
    --arg gopls ${pkgs.gopls}/bin/gopls \
    --arg json ${pkgs.vscode-langservers-extracted}/bin/vscode-json-language-server '
    (.plugins | map({key: .name, value: .lspServers[.name].command}) | from_entries)
      == {gopls: $gopls, json: $json}
  ' "$(jq -r '.extraKnownMarketplaces.sandbox.source.path' "$settings")/.claude-plugin/marketplace.json"
  touch $out
''
