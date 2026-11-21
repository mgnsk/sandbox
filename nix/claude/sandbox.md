# Sandbox

Every session runs inside `sandbox` (bwrap + pasta + seccomp), never on
the host. Know its limits up front instead of discovering them mid-task.

Not reachable - don't probe, plan around it:

- systemd/journalctl/loginctl, the host D-Bus (only a private bus with
  a Secret Service exists, which keeps this project's items in the host's
  keyring - storing or reading one may wait on an unlock prompt on the
  host), flatpak/portals
- X and pipewire sockets, and the Wayland one unless `$WAYLAND_DISPLAY` is
  set: then GUI apps open windows through a filtering proxy, without the
  clipboard, screen capture or a GPU (Electron needs `--no-sandbox
  --ozone-platform=wayland`)
- nested namespaces (bwrap, unshare, user namespaces)
- sudo/setuid (no_new_privs, all caps dropped), files owned by other
  users
- the host's /usr, /bin and /lib: every program comes from the nix store.
  The sandbox itself has only bash, nix, git, less, nano, ssh, jq, curl, rg,
  which, ps/pgrep/pkill, zip, unzip and the basic
  coreutils/grep/sed/tar/make set; every other tool comes from the project's dev shell
  (`nix develop`), plus `~/.nix-profile` when linked (only by a sandbox
  installed through home-manager). A missing command is
  missing, not misconfigured - use `nix shell nixpkgs#<pkg>` for one-off
  tools and tell the user to add it to the project's dev shell for good
- all of `~` is a per-project volume, not the host's - host files appear
  only where bound in (the project dir and whatever the user configured)
- writing outside `~`, the project, `/tmp` and `$XDG_RUNTIME_DIR`: the root
  is read-only, so nothing can be created in `/`, `/etc`, `/usr` or `/var`
- services on the host itself (its loopback or its own addresses), except
  ports the user listed in `SANDBOX_HOST_PORTS` when starting the sandbox,
  which appear at `127.0.0.1:<port>` inside. If a task needs one, ask the
  user to restart the sandbox with e.g. `SANDBOX_HOST_PORTS=5037`

Works: nix builds (through the host's nix-daemon, landing in the host
store), network, git push over ssh (gated by a popup on the host, which
the user can allow for the rest of the sandbox session; commit signing
with the user's signing key has no popup), `xdg-open` for http(s) URLs (opens the host's browser
after the same kind of popup), the project dir read-write.

`dangerouslyDisableSandbox` and the user's `!` prefix still run inside
this sandbox - never retry host-only things that way.

## Getting output from the host

`$SANDBOX_EXCHANGE` is a directory bound at the same path on the host,
read-only from inside - only the host writes there. It is the only
shared location: the sandbox has its own private `/tmp`
and `$XDG_RUNTIME_DIR` (tmpfs), so paths there - the scratchpad
included - don't exist on the host. Run `echo $SANDBOX_EXCHANGE` to get
the real path; never guess it. When host data is needed:

1. Say in one line why the host is needed.
2. Gather everything likely needed in one go, not one command per
   round trip.
3. Give a single bash block the user runs on the host that writes to
   the expanded literal path (not the variable, which is unset on the
   host) through `tee`, so the user sees the output too, each command
   preceded by a marker:
   ```sh
   { echo '### journalctl -b -u foo'; journalctl -b -u foo
     echo '### systemctl status foo'; systemctl status foo
   } 2>&1 | tee /home/.../exchange/foo.txt
   ```
   No sudo unless required, and say so when it is.
4. Stop and wait for the user to say done, then read the file - don't
   ask for a paste.

For host actions (restarting a service, ...) give the plain command
instead.
