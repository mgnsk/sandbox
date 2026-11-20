#!/bin/bash
# Starts nix-daemon as root, sets up tester's home for the demo named by
# $DEMO, then runs a login shell (or the given command) as tester. Both demos
# take the sandbox from the remote, github:mgnsk/sandbox, never from the
# checkout at /src, which only supplies the demo files:
#
#   flake         `sandbox` is `nix run github:mgnsk/sandbox --`, the default
#                 settings; ~/project is a Go project whose flake.nix brings
#                 the tools and whose sandbox.nix shapes the sandbox.
#   home-manager  `sandbox` comes from tester's home-manager config
#                 (programs.sandbox); ~/project is a plain directory, and
#                 ~/flake-project the flake demo's project.
set -euo pipefail

/nix/var/nix/profiles/default/bin/nix-daemon &
for _ in $(seq 50); do
	[ -S /nix/var/nix/daemon-socket/socket ] && break
	sleep 0.1
done

as_tester=(setpriv --reuid=tester --regid=tester --init-groups --reset-env)

case "${DEMO:-}" in
flake)
	# The README's alias, as a script so that `make demo-flake ARGS=...`
	# (no interactive shell) has it too.
	cat >/usr/local/bin/sandbox <<'EOF'
#!/bin/sh
exec nix run github:mgnsk/sandbox -- "$@"
EOF
	chmod +x /usr/local/bin/sandbox
	;;
home-manager) ;;
*)
	echo "entrypoint: DEMO must be flake or home-manager" >&2
	exit 1
	;;
esac

"${as_tester[@]}" env DEMO="$DEMO" bash -l <<'EOF'
set -euo pipefail

# A committed project: flakes see only tracked files, and the lock a real
# repo would have.
flake_project() {
	cp -r /src/demo/flake "$1"
	cd "$1"
	git init -q
	git add -A
	nix flake lock
	git add flake.lock
	git commit -qm 'Initial commit'
	cd
}

system=$(nix eval --raw --impure --expr builtins.currentSystem)

case $DEMO in
flake)
	# The host's git identity, which sandbox.nix takes in (git.fromHost).
	git config --global user.name 'Demo Tester'
	git config --global user.email tester@example.com
	git config --global init.defaultBranch main
	flake_project ~/project
	;;
home-manager)
	mkdir -p ~/.config
	cp -r /src/demo/home-manager ~/.config/home-manager
	mv ~/.config/home-manager/project ~/project
	sed -i "s/system = \"x86_64-linux\"/system = \"$system\"/" ~/.config/home-manager/flake.nix
	git -C ~/.config/home-manager init -q
	git -C ~/.config/home-manager add -A
	# The first switch of a new install, as home-manager's docs give it;
	# later ones run the installed home-manager. -b: Debian's own
	# ~/.bashrc and ~/.profile are in the way of programs.bash.
	nix run home-manager/master -- switch -b backup --flake ~/.config/home-manager#tester
	git -C ~/project init -q
	git -C ~/project add -A
	git -C ~/project commit -qm 'Initial commit'
	flake_project ~/flake-project
	;;
esac
EOF

cd /home/tester/project
if [ $# -eq 0 ]; then
	exec "${as_tester[@]}" bash -l
fi
exec "${as_tester[@]}" bash -lc "$*"
