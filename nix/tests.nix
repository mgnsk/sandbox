# The unit tests, as a check. The tests that start a real sandbox skip
# themselves: the nix build sandbox has no unprivileged user namespaces.
{
  cacert,
  callPackage,
  python3,
  runCommand,
}:
let
  p = callPackage ./packages.nix { };
  python = python3.withPackages (ps: [
    ps.dbus-fast
    ps.graphql-core
    ps.pytest
  ]);
in
runCommand "sandbox-tests"
  {
    nativeBuildInputs = [
      python
      p.gh
      p.forgejo-cli
    ];
  }
  ''
    cp -r ${../src} src
    cp -r ${../tests} tests
    chmod -R u+w .
    export HOME=$TMPDIR/home
    # fj loads the system's CA certificates even for a unix socket.
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
    mkdir -p $HOME
    python -m pytest -q -p no:cacheprovider tests
    touch $out
  ''
