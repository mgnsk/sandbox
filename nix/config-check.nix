# The launcher's config from a fixture module, and with Claude Code brought
# by the user (claude.package = null).
{
  evalSandbox,
  pkgs,
  runCommand,
  jq,
}:
let
  configFile = modules: (evalSandbox { inherit pkgs modules; }).configFile;
  config = configFile [ ./fixtures/settings.nix ];
  withoutClaude = configFile [ { claude.package = null; } ];
in
runCommand "sandbox-config-check" { nativeBuildInputs = [ jq ]; } ''
  jq -e '
    .guards.forgejo == true
    and .hostPorts == ["5432"]
    and .default.env.EDITOR == "nvim"
    and ([.profiles[] | {name, paths, claudeApiKey}]
         == [{name: "work", paths: ["~/work"], claudeApiKey: true}])
  ' ${config}
  bin=$(jq -r '.default.env.PATH | split(":")[0]' ${config})
  test -x "$bin/hello"
  test -x "$bin/claude"
  test ! -e "$(jq -r '.default.env.PATH | split(":")[0]' ${withoutClaude})/claude"
  test -f "$(jq -r '.default.claudeDir' ${withoutClaude})/managed-settings.json"
  touch $out
''
