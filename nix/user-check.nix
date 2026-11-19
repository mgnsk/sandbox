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
  touch $out
''
