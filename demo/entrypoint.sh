#!/bin/bash
# Starts nix-daemon as root, installs a sandbox built with the checkout
# mounted at /src (and its default settings) into tester's profile, then runs
# a login shell (or the given command) as tester.
set -euo pipefail

/nix/var/nix/profiles/default/bin/nix-daemon &
for _ in $(seq 50); do
	[ -S /nix/var/nix/daemon-socket/socket ] && break
	sleep 0.1
done

as_tester=(setpriv --reuid=tester --regid=tester --init-groups --reset-env)

"${as_tester[@]}" bash -lc 'nix profile remove --all 2>/dev/null || true; nix profile add --impure --expr "
  let
    s = builtins.getFlake \"path:/src\";
    pkgs = import s.inputs.nixpkgs {
      system = builtins.currentSystem;
      config.allowUnfreePredicate = p: s.inputs.nixpkgs.lib.getName p == \"claude-code\";
    };
  in s.lib.mkSandbox { inherit pkgs; }
"'

if [ $# -eq 0 ]; then
	exec "${as_tester[@]}" bash -l
fi
exec "${as_tester[@]}" bash -lc "$*"
