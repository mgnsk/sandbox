# user.nix on a fixture config.nix, and the default package's pointer to it.
{
  lib,
  pkgs,
  runCommand,
  jq,
}:
let
  config = import ./user.nix {
    nixpkgs = pkgs.path;
    inherit (pkgs.stdenv.hostPlatform) system;
    file = ./fixtures/config.nix;
  };
  withUser =
    (import ./eval.nix { inherit lib; } {
      inherit pkgs;
      modules = [ { userConfig.enable = true; } ];
    }).configFile;
  # Claude Code brought by the user: the managed config without the package.
  withoutClaude =
    (import ./eval.nix { inherit lib; } {
      inherit pkgs;
      modules = [ { claude.package = null; } ];
    }).configFile;
in
runCommand "sandbox-user-check" { nativeBuildInputs = [ jq ]; } ''
  jq -e '
    .userConfig == null
    and .guards.forgejo == true
    and .hostPorts == ["5432"]
    and .default.env.EDITOR == "nvim"
    and ([.profiles[] | {name, paths, claudeApiKey}]
         == [{name: "work", paths: ["~/work"], claudeApiKey: true}])
  ' ${config}
  test -x "$(jq -r '.default.env.PATH | split(":")[0]' ${config})/hello"
  jq -e '.userConfig.eval | endswith("/user.nix")' ${withUser}
  test -x "$(jq -r '.default.env.PATH | split(":")[0]' ${config})/claude"
  test ! -e "$(jq -r '.default.env.PATH | split(":")[0]' ${withoutClaude})/claude"
  test -f "$(jq -r '.default.claudeDir' ${withoutClaude})/managed-settings.json"
  touch $out
''
