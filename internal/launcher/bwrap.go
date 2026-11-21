package launcher

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
)

// bwrapArgs are bwrap's arguments, built up in order: bwrap layers mounts in
// argv order, later ones over earlier ones.
type bwrapArgs []string

func (a *bwrapArgs) add(args ...string)      { *a = append(*a, args...) }
func (a *bwrapArgs) bind(src, dst string)    { a.add("--bind", src, dst) }
func (a *bwrapArgs) roBind(src, dst string)  { a.add("--ro-bind", src, dst) }
func (a *bwrapArgs) setenv(name, val string) { a.add("--setenv", name, val) }

// insideEnv is the environment inside: passed-through host vars, then the
// profile's own (PATH included), with $HOME etc. expanded.
func insideEnv(cfg *config, p profile, vars map[string]string) map[string]string {
	env := map[string]string{
		"HOME":            vars["HOME"],
		"USER":            vars["USER"],
		"LOGNAME":         vars["USER"],
		"XDG_RUNTIME_DIR": vars["XDG_RUNTIME_DIR"],
	}
	for _, name := range cfg.PassEnv {
		if value, ok := os.LookupEnv(name); ok {
			env[name] = value
		}
	}
	for name, value := range p.Env {
		env[name] = expand(value, vars)
	}
	return env
}

// baseArgs are the namespaces, environment and the filesystem every
// sandbox has.
func baseArgs(cfg *config, env map[string]string) bwrapArgs {
	a := bwrapArgs{
		// Includes --unshare-pid, so a sandbox shows up as two bwrap
		// processes on the host: the outer one waits in the host's pid
		// namespace to relay the exit status, the inner one is pid 1
		// inside, reaping zombies and forwarding signals.
		"--unshare-all",
		"--unshare-user",
		"--disable-userns",
		// pasta maps the invoking user to uid 0 in its own userns; pin the
		// real uid/gid so bwrap doesn't inherit that and look like real
		// root.
		"--uid", strconv.Itoa(os.Getuid()),
		"--gid", strconv.Itoa(os.Getgid()),
		// Retains the netns bwrap starts in - a fresh one from pasta, not
		// the host's. Sharing the host's would also expose its abstract
		// AF_UNIX namespace (e.g. @/tmp/.X11-unix/X0, which Xwayland
		// accepts unauthenticated local connections on).
		"--share-net",
		"--die-with-parent",
		"--cap-drop", "ALL",
		// Otherwise the host env passes through untouched, e.g. a GitHub
		// token in the host shell would reach the API directly, bypassing
		// the gh write popups.
		"--clearenv",
	}
	for _, name := range slices.Sorted(maps.Keys(env)) {
		a.setenv(name, env[name])
	}
	a.add(
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--tmpfs", env["XDG_RUNTIME_DIR"],
	)
	// Read-only is enough for builds to land in the host store: the
	// daemon socket stays connectable on a ro mount, and the host's
	// nix-daemon does the actual store writes.
	a.roBind("/nix", "/nix")
	// Nothing of the host's /usr, /bin or /lib: the few fixed paths
	// programs expect, from the store.
	a.roBind(cfg.FHS.Bin, "/bin")
	a.roBind(cfg.FHS.UsrBin, "/usr/bin")
	for src, dst := range map[string]string{
		cfg.FHS.BashCompletion: "/usr/share/bash-completion",
		cfg.FHS.Bashrc:         "/etc/bashrc",
		cfg.FHS.Profile:        "/etc/profile",
		// What the agents inside read about the sandbox (mkClaude's
		// system prompt).
		cfg.FHS.AgentsMd: "/etc/sandbox/AGENTS.md",
	} {
		if src != "" {
			a.roBind(src, dst)
		}
	}
	a.roBind(cfg.FHS.NixLd, cfg.FHS.LdPath)
	a.roBind(cfg.FHS.SSL, "/etc/ssl")
	for _, path := range cfg.HostEtc {
		a.add("--ro-bind-try", path, path)
	}
	return a
}

// bindArgs are the profile's extra binds, then the project.
func bindArgs(binds []bind, vars map[string]string, project string) bwrapArgs {
	var a bwrapArgs
	for _, b := range binds {
		src := realpath(expand(b.Src, vars))
		dst := src
		if b.Dst != "" {
			dst = expand(b.Dst, vars)
		}
		if src == project && dst == src {
			// The project bind below covers it, read-write and .git
			// included: a repo bound for reference elsewhere is the project
			// here.
			continue
		}
		flag := "--ro-bind"
		if b.Mode == "rw" {
			flag = "--bind"
		}
		if b.Optional {
			flag += "-try"
		}
		a.add(flag, src, dst)
		if b.HideGit && isDir(filepath.Join(src, ".git")) {
			// Its history, with whatever was ever committed and removed
			// again, is none of another project's business.
			a.add("--tmpfs", filepath.Join(dst, ".git"))
		}
	}
	// The whole work tree rather than just $PWD, so starting in a
	// subdirectory still gets .git.
	a.bind(project, project)
	return a
}

// exchangeArgs: a drop box for output of commands the user runs on the
// host, read back instead of pasted. Bound at its host path so a command
// naming $SANDBOX_EXCHANGE's value runs verbatim on either side.
//
// Read-only: only the host writes here, and a symlink a sandbox planted
// would point that write at any host file. Links left from when it was
// read-write are dropped.
func exchangeArgs(volumeDir string) (bwrapArgs, error) {
	exchange := filepath.Join(volumeDir, "exchange")
	if err := os.MkdirAll(exchange, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(exchange, 0o700); err != nil {
		return nil, err
	}
	_ = filepath.WalkDir(exchange, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink != 0 {
			_ = os.Remove(path)
		}
		return nil
	})
	var a bwrapArgs
	a.roBind(exchange, exchange)
	a.setenv("SANDBOX_EXCHANGE", exchange)
	return a, nil
}
