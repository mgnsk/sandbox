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
  fetchFromGitHub,
  rustPlatform,
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
  # clients. As released (0.1.5) it only leaves the others out of the
  # registry's listing, and still forwards a bind of one, by a guessed name,
  # to the compositor; from this commit it refuses the bind of a global it
  # didn't announce, or of a higher version than it announced
  # (mahkoh/wl-proxy#144).
  # TODO: back to nixpkgs' wl-proxy as it is once that has a release with
  # the fix (one after 0.1.5).
  wl-veil = wl-proxy.overrideAttrs (
    finalAttrs: old: {
      pname = "sandbox-wl-veil";
      version = "0.1.5-unstable-2026-11-20";
      src = fetchFromGitHub {
        owner = "mahkoh";
        repo = "wl-proxy";
        rev = "deff40c548e38f1d561d7da737a25609377d0965";
        hash = "sha256-D2u/1yErzJi//Y4LLLGRlcxxHvbhAH7z4WFERKdeSAw=";
      };
      # Its own, of this source: the sandbox is built with the user's
      # nixpkgs through home-manager, and not every one makes the
      # package's from an overridden src.
      cargoDeps = rustPlatform.fetchCargoVendor {
        inherit (finalAttrs) pname version src;
        hash = "sha256-mdJmlbtWwnf1OETZi9XqPfdYmMg2bjFC7MVK1A6/FQ4=";
      };
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
    }
  );
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
