# The tests, as a check, against the built binary. The tests that start a
# real sandbox skip themselves: the nix build sandbox has no unprivileged
# user namespaces.
{
  cacert,
  callPackage,
  dbus,
  python3,
  runCommand,
}:
let
  p = callPackage ./packages.nix { };
  python = python3.withPackages (ps: [
    ps.cryptography
    ps.dbus-fast
    ps.pytest
    ps.pyte
  ]);
in
runCommand "sandbox-tests"
  {
    nativeBuildInputs = [
      python
      dbus
      p.gh
      p.forgejo-cli
    ];
  }
  ''
    cp -r ${../tests} tests
    chmod -R u+w .
    export HOME=$TMPDIR/home
    # rustls-platform-verifier wants a system bundle even when a test
    # replaces it.
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
    mkdir -p $HOME
    export SANDBOX_BIN_DIR=${p.sandbox}/bin
    python -m pytest -q -p no:cacheprovider tests
    touch $out
  ''
