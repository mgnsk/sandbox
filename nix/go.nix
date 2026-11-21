# sandbox-bin: the launcher, init and the guards, as subcommands of one
# binary.
{
  lib,
  buildGoModule,
}:
buildGoModule {
  pname = "sandbox-bin";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
    ];
  };
  # After a go.mod or go.sum change: make vendor-hash.
  vendorHash = "sha256-lfYMMsKohShLgzo6tImA8nO3+lerf+fJo2r45NLlHII=";
  subPackages = [ "cmd/sandbox-bin" ];
  # The tests are a check of their own, see tests.nix.
  doCheck = false;
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
  ];
  meta.mainProgram = "sandbox-bin";
}
