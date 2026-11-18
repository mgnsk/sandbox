# The unit tests, as a check. The tests that start a real sandbox skip
# themselves: the nix build sandbox has no unprivileged user namespaces.
# With sandbox-go, its programs run in place of src/'s.
{
  lib,
  sandbox-go ? null,
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
    ps.graphql-core
    ps.pytest
    ps.pyte
  ]);
in
runCommand (if sandbox-go == null then "sandbox-tests" else "sandbox-go-tests")
  {
    nativeBuildInputs = [
      python
      dbus
      p.gh
      p.forgejo-cli
    ];
  }
  ''
    cp -r ${../src} src
    cp -r ${../tests} tests
    chmod -R u+w .
    export HOME=$TMPDIR/home
    # rustls-platform-verifier wants a system bundle even when a test
    # replaces it.
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
    mkdir -p $HOME
    ${lib.optionalString (sandbox-go != null) "export SANDBOX_GUARD_CMD='${sandbox-go}/bin/{name}'"}
    python -m pytest -q -p no:cacheprovider tests
    touch $out
  ''
