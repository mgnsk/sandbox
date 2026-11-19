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
      ../e2e
    ];
  };
  # Update with lib.fakeHash and the hash nix reports after a go.mod change.
  vendorHash = "sha256-HxKpif9cCd0lZHrdJYVfIZf3V8JpJezRO2fCihbB4pU=";
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
