#!/bin/bash
# Starts nix-daemon as root, installs the sandbox from the checkout mounted
# at /src into tester's profile, then runs a login shell (or the given
# command) as tester.
set -euo pipefail

/nix/var/nix/profiles/default/bin/nix-daemon &
for _ in $(seq 50); do
	[ -S /nix/var/nix/daemon-socket/socket ] && break
	sleep 0.1
done

as_tester=(setpriv --reuid=tester --regid=tester --init-groups --reset-env)

"${as_tester[@]}" bash -lc 'nix profile remove --all 2>/dev/null || true; nix profile add /src'

if [ $# -eq 0 ]; then
	exec "${as_tester[@]}" bash -l
fi
exec "${as_tester[@]}" bash -lc "$*"
