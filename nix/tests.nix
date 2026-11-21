# The Go tests, as a check, with gh, fj and dbus-daemon for
# the tests that run them. Not the real-sandbox tests (e2e), which aren't in
# this source: the nix build sandbox has neither the unprivileged user
# namespaces nor the nix daemon they need, and the tests here that need one
# skip themselves.
{
  cacert,
  callPackage,
  dbus,
  forgejo-cli,
  gh,
  libseccomp,
  pkg-config,
}:
let
  p = callPackage ./packages.nix { };
in
p.sandbox.overrideAttrs {
  pname = "sandbox-tests";
  doCheck = true;
  # internal/seccomp links libseccomp; cgo only for the tests, so the
  # binary built before them doesn't refer to go.
  buildInputs = [ libseccomp ];
  nativeCheckInputs = [
    pkg-config
    dbus
    gh
    forgejo-cli
  ];
  checkPhase = ''
    runHook preCheck
    export HOME=$TMPDIR/home
    mkdir -p $HOME
    # rustls-platform-verifier (fj) wants a system bundle even when a test
    # replaces it.
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
    CGO_ENABLED=1 go test ./...
    runHook postCheck
  '';
}
