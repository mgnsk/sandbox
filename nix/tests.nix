# The Go tests, as a check, with the gh and fj wrappers and dbus-daemon for
# the tests that run them. The real-sandbox tests (e2e), and the others that
# need unprivileged user namespaces or a nix daemon, skip themselves: the nix
# build sandbox has neither.
{
  cacert,
  callPackage,
  dbus,
}:
let
  p = callPackage ./packages.nix { };
in
p.sandbox.overrideAttrs {
  pname = "sandbox-tests";
  doCheck = true;
  nativeCheckInputs = [
    dbus
    p.gh
    p.forgejo-cli
  ];
  checkPhase = ''
    runHook preCheck
    export HOME=$TMPDIR/home
    mkdir -p $HOME
    # rustls-platform-verifier (fj) wants a system bundle even when a test
    # replaces it.
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
    go test ./...
    runHook postCheck
  '';
}
