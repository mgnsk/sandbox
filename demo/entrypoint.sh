#!/bin/bash
# Starts nix-daemon as root, then, as tester: installs the demo distribution
# (demo/distribution, a tools flake with `sandbox` in it) into the nix
# profile the way a user installs their organisation's tools, sets up
# ~/project (demo/project, a Go project with its own dev shell), and runs a
# login shell (or the given command) there. The distribution takes the
# sandbox from the remote, github:mgnsk/sandbox, never from the checkout at
# /src, which only supplies the demo files.
set -euo pipefail

/nix/var/nix/profiles/default/bin/nix-daemon &
for _ in $(seq 50); do
	[ -S /nix/var/nix/daemon-socket/socket ] && break
	sleep 0.1
done

as_tester=(setpriv --reuid=tester --regid=tester --init-groups --reset-env)

"${as_tester[@]}" bash -l <<'EOF2'
set -euo pipefail

# A committed repo: flakes see only tracked files, and the lock a real repo
# would have.
repo() {
	cp -r "$1" "$2"
	cd "$2"
	git init -q
	git add -A
	nix flake lock
	git add flake.lock
	git commit -qm 'Initial commit'
	cd
}

# The host's git identity, which the distribution takes in (git.fromHost).
git config --global user.name 'Demo Tester'
git config --global user.email tester@example.com
git config --global init.defaultBranch main

repo /src/demo/distribution ~/tools
nix profile add ~/tools#sandbox
repo /src/demo/project ~/project
EOF2

cd /home/tester/project
if [ $# -eq 0 ]; then
	exec "${as_tester[@]}" bash -l
fi
exec "${as_tester[@]}" bash -lc "$*"
