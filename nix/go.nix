# The launcher, sandbox-init and the guards: one binary that runs as the
# program it is started under (argv[0]), with a link per program.
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
  # Update with lib.fakeHash and the hash nix reports after a go.mod change.
  vendorHash = "sha256-KOaiEQl3htqD9gXHNb/Kd5hGGTYna5qb806v6OZCj94=";
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
  ];
  # Each program it runs as, linked to the binary.
  programs = lib.filter (p: p != "") (
    lib.splitString "\n" (builtins.readFile ../cmd/sandbox/programs)
  );
  postInstall = ''
    for p in $programs; do
      [ "$p" = sandbox ] || ln -s sandbox $out/bin/$p
    done
  '';
  meta.mainProgram = "sandbox";
}
