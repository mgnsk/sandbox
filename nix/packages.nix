# Store-built pieces of the sandbox, independent of any configuration.
{
  lib,
  runCommand,
  symlinkJoin,
  writeShellScript,
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
    ps.cryptography
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

  # Upstream gh and fj, pointed at their guard: with the launcher's
  # SANDBOX_GH_PROXY / SANDBOX_FJ_PROXY set, the wrapper makes it the
  # client's only proxy and SANDBOX_CA_FILE (the system bundle plus the
  # guards' CAs) its SSL_CERT_FILE, so only these clients (and their
  # children) trust the guards' certificates. Without the variables they're
  # plain gh and fj. Not a security control: unwrapped, gh only has the
  # placeholder token, and fj none.
  viaGuard =
    pkg: exe: var:
    let
      wrapper = writeShellScript exe ''
        if [ -n "''${${var}:-}" ]; then
          unset http_proxy https_proxy HTTP_PROXY ALL_PROXY all_proxy NO_PROXY no_proxy
          export HTTPS_PROXY="''${${var}}"
          if [ -n "''${SANDBOX_CA_FILE:-}" ]; then
            export SSL_CERT_FILE="$SANDBOX_CA_FILE"
          fi
        fi
        exec ${lib.getExe' pkg exe} "$@"
      '';
    in
    symlinkJoin {
      name = "${exe}-sandbox-${pkg.version}";
      paths = [ pkg ];
      postBuild = ''
        rm $out/bin/${exe}
        ln -s ${wrapper} $out/bin/${exe}
      '';
      meta = pkg.meta // {
        mainProgram = exe;
      };
    };

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
  gh = viaGuard gh "gh" "SANDBOX_GH_PROXY";
  forgejo-cli = viaGuard forgejo-cli "fj" "SANDBOX_FJ_PROXY";
}
