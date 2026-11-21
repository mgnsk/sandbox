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
  fails = modules: !(builtins.tryEval (configFile modules).drvPath).success;
in
# No configuration adds tools.
assert fails [ { packages = [ pkgs.hello ]; } ];
assert fails [ { basePackages = [ ]; } ];
# Claude Code's config is the project's (sandbox.lib.mkClaude), and a
# project file picks no profile.
assert fails [ { claude.memory = "x"; } ];
assert fails [ { profiles.x.projectFiles = [ "flake.nix" ]; } ];
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
  grep -q '^# Sandbox' "$(jq -r '.fhs.agentsMd' ${config})"
  test -f "$(jq -r '.fhs.bashCompletion' ${config})/bash_completion"
  grep -q bash_completion "$(jq -r '.fhs.bashrc' ${config})"
  grep -q PS1= "$(jq -r '.fhs.bashrc' ${config})"
  grep -q /etc/bashrc "$(jq -r '.fhs.profile' ${config})"
  touch $out
''
