# The Go rewrite: one binary that runs as the program it is started under
# (argv[0]), with a link per program. Programs move here from src/ one at a
# time; until the launcher does, the sandbox package still runs src/.
{
  lib,
  buildGoModule,
}:
buildGoModule {
  pname = "sandbox-go";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../cmd
      ../internal
    ];
  };
  vendorHash = null;
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
      ln -s sandbox $out/bin/$p
    done
  '';
  meta.mainProgram = "sandbox";
}
