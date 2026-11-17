# Store-built pieces of the sandbox, independent of any configuration.
{
  lib,
  runCommand,
  writeShellScriptBin,
  python3,
  gh,
  forgejo-cli,
  bash,
  coreutils,
}:
let
  # Runs the launcher (on the host), sandbox-init (inside) and the guards
  # (on the host).
  python = python3.withPackages (ps: [
    ps.dbus-fast
    ps.graphql-core
  ]);

  # The launcher, sandbox-init, guards and xdg-open shim, run as
  # `python -E -s <file>`: -E/-s keep a project shell's PYTHONPATH and user
  # site-packages out, and the script's own directory on sys.path is what
  # lets the guards import guard_popup/api_proxy.
  src = lib.cleanSourceWith {
    name = "sandbox-src";
    src = ../src;
    filter = path: _type: !(lib.hasSuffix ".pyc" path) && baseNameOf path != "__pycache__";
  };

  # bwrap takes raw cBPF, not a policy, so it's compiled from the libseccomp
  # rules here rather than committed as an opaque blob.
  seccomp =
    runCommand "sandbox-seccomp.bpf"
      { nativeBuildInputs = [ (python3.withPackages (p: [ p.seccomp ])) ]; }
      ''
        python3 ${./seccomp.py} > $out
      '';

  # Both clients are patched, so they miss the binary cache and build from
  # source. Their upstream test suites are skipped: nixpkgs already runs
  # them on the unpatched sources, and the patches have their own tests.

  # Sends its API requests over GH_HTTP_UNIX_SOCKET when set, to the host
  # proxy holding the real token. Recheck on gh bumps:
  # tests/test_gh_unix_socket_patch.py fails if the patch stops applying or
  # stops having an effect.
  ghPatched = gh.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [ ./patches/gh-unix-socket.patch ];
    doCheck = false;
  });

  # The same for fj, via FJ_HTTP_UNIX_SOCKET. The client is built in the
  # vendored forgejo-api crate, so the patch goes there; the vendor dir is
  # copied writable before postPatch, and its checksums don't cover the
  # files. Recheck on bumps: the path names the crate version, and
  # tests/test_forgejo_api_unix_socket_patch.py fails if the patch stops
  # having an effect.
  forgejoPatched = forgejo-cli.overrideAttrs (old: {
    postPatch = (old.postPatch or "") + ''
      patch -p1 -d "$cargoDepsCopy/source-registry-0/forgejo-api-0.12.0" \
        < ${./patches/forgejo-api-unix-socket.patch}
    '';
    doCheck = false;
  });

  # xdg-open inside: hands the URL to open-url-guard on the host.
  xdg-open = writeShellScriptBin "xdg-open" ''
    exec ${python.interpreter} -E -s ${src}/sandbox-xdg-open "$@"
  '';

  # The few fixed paths programs expect, in place of the host's /bin and
  # /usr/bin: /bin/sh for system() and Makefiles, /usr/bin/env and /bin/env
  # for shebangs, /usr/bin/xdg-open for BROWSER.
  fhs = runCommand "sandbox-fhs" { } ''
    mkdir -p $out/bin $out/usr/bin
    ln -s ${bash}/bin/bash $out/bin/sh
    ln -s ${bash}/bin/bash $out/bin/bash
    ln -s ${coreutils}/bin/env $out/bin/env
    ln -s ${coreutils}/bin/env $out/usr/bin/env
    ln -s ${xdg-open}/bin/xdg-open $out/usr/bin/xdg-open
  '';
in
{
  inherit
    python
    src
    seccomp
    xdg-open
    fhs
    ;
  gh = ghPatched;
  forgejo-cli = forgejoPatched;
}
