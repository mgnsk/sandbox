# Store-built pieces of the sandbox, independent of any configuration.
{
  lib,
  runCommand,
  symlinkJoin,
  writeShellScript,
  writeShellScriptBin,
  callPackage,
  libseccomp,
  pkg-config,
  gh,
  forgejo-cli,
  bash,
  coreutils,
}:
let
  # The launcher, sandbox-init and the guards: one binary, run under each
  # program's name.
  sandbox = callPackage ./go.nix { };

  # Writes the seccomp filter: the rules in internal/seccomp through
  # libseccomp, so it needs cgo, which the sandbox binary goes without.
  seccomp-bpf = sandbox.overrideAttrs (old: {
    pname = "sandbox-seccomp-bpf";
    subPackages = [ "cmd/seccomp-bpf" ];
    env = old.env // {
      CGO_ENABLED = 1;
    };
    nativeBuildInputs = old.nativeBuildInputs ++ [ pkg-config ];
    buildInputs = [ libseccomp ];
    postInstall = "";
    meta.mainProgram = "seccomp-bpf";
  });

  # bwrap takes raw cBPF, not a policy, so it's generated here rather than
  # committed as an opaque blob.
  seccomp = runCommand "sandbox-seccomp.bpf" { } ''
    ${lib.getExe seccomp-bpf} > $out
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
    exec ${sandbox}/bin/sandbox-xdg-open "$@"
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
    sandbox
    seccomp
    xdg-open
    fhs
    ;
  gh = viaGuard gh "gh" "SANDBOX_GH_PROXY";
  forgejo-cli = viaGuard forgejo-cli "fj" "SANDBOX_FJ_PROXY";
}
