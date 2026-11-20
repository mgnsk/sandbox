# Store-built pieces of the sandbox, independent of any configuration.
{
  lib,
  runCommand,
  writeShellScriptBin,
  callPackage,
  libseccomp,
  pkg-config,
  bash,
  coreutils,
  wl-proxy,
}:
let
  # sandbox-bin: the launcher, init and the guards, as subcommands.
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
    meta.mainProgram = "seccomp-bpf";
  });

  # bwrap takes raw cBPF, not a policy, so it's generated here rather than
  # committed as an opaque blob.
  seccomp = runCommand "sandbox-seccomp.bpf" { } ''
    ${lib.getExe seccomp-bpf} > $out
  '';

  # xdg-open inside: hands the URL to open-url-guard on the host.
  xdg-open = writeShellScriptBin "xdg-open" ''
    exec ${lib.getExe sandbox} xdg-open "$@"
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

  # The Wayland guard's proxy: wl-veil passes only the listed globals on to
  # clients. As released it only leaves the others out of the registry's
  # listing, and still forwards a bind of one, by a guessed name, to the
  # compositor; the patch has it forward binds of announced globals only.
  # TODO: drop the patch once wl-veil refuses such binds upstream.
  wl-veil = wl-proxy.overrideAttrs (old: {
    pname = "sandbox-wl-veil";
    patches = (old.patches or [ ]) ++ [ ./patches/wl-veil-bind.patch ];
    cargoBuildFlags = [
      "--bin"
      "wl-veil"
    ];
    # The other programs of the package, their completions and its tests
    # aren't the sandbox's.
    postInstall = "";
    doCheck = false;
    meta = old.meta // {
      mainProgram = "wl-veil";
    };
  });
in
{
  inherit
    sandbox
    seccomp
    xdg-open
    fhs
    wl-veil
    ;
}
