// Package launcher is the sandbox launcher: it runs a command (default: a
// login bash) in a per-project sandbox.
//
//	sandbox-bin launch --config CONFIG.json [OPTIONS] [--] [COMMAND...]
//
// bwrap + pasta + seccomp, with guard proxies on the host for ssh-agent, a
// Secret Service, the GitHub, Forgejo and Claude APIs and opening URLs. See
// SECURITY.md for the threat model; the reasoning for individual flags is
// next to them here.
//
// Everything it runs - bwrap, pasta, the guards, the environment inside -
// comes from store paths in CONFIG.json or from this binary, never from the
// host's PATH. The guards and init are subcommands of this binary.
//
// A project's sandbox.nix adds to the selected profile. It is evaluated
// inside a sandbox of the project, and what it asks for beyond the inside
// (binds, host ports) is shown on the terminal for approval first.
package launcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/mgnsk/sandbox/internal/popuprelay"
)

// launcher is one start of a sandbox.
type launcher struct {
	self       string // This binary, whose subcommands the guards and init are.
	configPath string
	cfg        *config
	opts       Options
	command    []string

	home, user, runtimeDir string
	vars                   map[string]string // What config values may name: $HOME, $USER, $XDG_RUNTIME_DIR.
	cwd, project           string
	volumeDir              string
}

// signalError is a signal that stopped the start.
type signalError struct{ sig syscall.Signal }

func (e signalError) Error() string { return "interrupted" }

// Main runs command in the sandbox configured at configPath; the exit status.
func Main(configPath string, opts Options, command []string) int {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	code, err := run(ctx, cancel, configPath, opts, command, signals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
		code = 1
	}
	// Stopped by a signal before the sandbox ran: end as the signal would,
	// now that everything is cleaned up.
	if serr, ok := context.Cause(ctx).(signalError); ok {
		signal.Reset(serr.sig)
		_ = syscall.Kill(os.Getpid(), serr.sig)
		return 128 + int(serr.sig)
	}
	return code
}

func run(ctx context.Context, cancel context.CancelCauseFunc, configPath string, opts Options, command []string, signals chan os.Signal) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	l := &launcher{self: self, configPath: configPath, opts: opts, command: command}
	if l.cfg, err = readConfig(l.configPath); err != nil {
		return 0, err
	}

	// Until the sandbox runs, a signal stops the start.
	starting := make(chan struct{})
	go func() {
		select {
		case sig := <-signals:
			cancel(signalError{sig.(syscall.Signal)})
		case <-starting:
		}
	}()
	g := newGuards(self, l.cfg)
	defer g.close()
	argv, popups, err := l.prepare(ctx, g)
	close(starting)
	if err == nil {
		err = context.Cause(ctx)
	}
	if err != nil || argv == nil {
		return 0, err
	}
	return runSandbox(argv, popups, signals)
}

// prepare checks where the launcher runs, starts the guards and builds the
// command line; nil for an option that's done without a sandbox.
func (l *launcher) prepare(ctx context.Context, g *guards) ([]string, *net.UnixListener, error) {
	if err := l.locate(); err != nil {
		return nil, nil, err
	}
	if err := l.makeVolume(); err != nil {
		return nil, nil, err
	}

	prof := selectProfile(l.cfg, l.cwd, l.project, l.vars)
	switch {
	case l.opts.ClaudeAPIKey:
		if !prof.ClaudeAPIKey {
			name := prof.Name
			if name == "" {
				name = "default"
			}
			return nil, nil, fmt.Errorf("--claude-api-key needs guards.claudeApiKey.enable for this project's profile (%s)", name)
		}
		return nil, nil, claudeAPIKey(l.volumeDir, true)
	}

	hostPorts := l.cfg.HostPorts
	if !l.opts.NoProjectConfig && lexists(filepath.Join(l.project, projectFileName)) {
		m, err := l.projectManifest(ctx, prof.ClaudeDir)
		if err != nil {
			return nil, nil, err
		}
		projectTokenCommands(l.cfg, prof, m)
		if err := l.approveProject(m); err != nil {
			return nil, nil, err
		}
		prof = withProjectTokenCommands(applyProject(prof, m), m)
		hostPorts = slices.Concat(hostPorts, m.HostPorts)
		if len(l.command) == 0 {
			l.command = m.Command
		}
	}
	tcp, udp, err := parseHostPorts(hostPortSpecs(hostPorts))
	if err != nil {
		return nil, nil, err
	}
	if prof.ClaudeAPIKey {
		if err := claudeAPIKey(l.volumeDir, false); err != nil {
			return nil, nil, err
		}
	}
	if unix.Access(l.cfg.Seccomp, unix.R_OK) != nil {
		return nil, nil, fmt.Errorf("missing seccomp filter %s", l.cfg.Seccomp)
	}

	a := baseArgs(l.cfg, insideEnv(l.cfg, prof, l.vars))
	// Must precede every mount under $HOME - bwrap layers mounts in argv
	// order, so those narrower binds shadow the volume, not the other way
	// round.
	a.bind(l.homeVolume(), l.home)

	// Before the guards start, so they get its path.
	if popuprelay.Usable() {
		if err := g.listenPopups(); err != nil {
			return nil, nil, err
		}
	}
	if err := l.startGuards(ctx, g, &a, prof); err != nil {
		return nil, nil, err
	}

	// Claude Code's managed settings, memory and MCP servers: managed
	// settings outrank user/project/local ones, so ~/.claude in the volume
	// can't override them.
	if prof.ClaudeDir != "" {
		a.roBind(prof.ClaudeDir, "/etc/claude-code")
	}
	resolver, err := l.resolvConf(g, &a)
	if err != nil {
		return nil, nil, err
	}
	exchange, err := exchangeArgs(l.volumeDir)
	if err != nil {
		return nil, nil, err
	}
	a.add(exchange...)
	a.add(bindArgs(prof.Binds, l.vars, l.project)...)
	l.initArgs(&a)

	addrs, err := hostAddresses()
	if err != nil {
		return nil, nil, err
	}
	return pastaArgv(l.cfg, slices.Concat(tcp, g.tcpPorts), udp, addrs, a, resolver), g.popups, nil
}

// locate finds the user, home and project, and checks the launcher may run
// here.
func (l *launcher) locate() error {
	// Physical, not $PWD: a symlink to ~ mustn't slip past the checks, and
	// the binds name the real path.
	cwd, err := syscall.Getwd()
	if err != nil {
		return err
	}
	_ = os.Chdir(cwd)
	homeEnv, ok := os.LookupEnv("HOME")
	if !ok {
		return errors.New("HOME is not set")
	}
	l.cwd, l.home = cwd, realpath(homeEnv)
	l.user = os.Getenv("USER")
	if l.user == "" {
		l.user = os.Getenv("LOGNAME")
	}
	if l.user == "" {
		l.user = strconv.Itoa(os.Getuid())
	}
	l.runtimeDir = os.Getenv("XDG_RUNTIME_DIR")
	if l.runtimeDir == "" {
		l.runtimeDir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	l.vars = map[string]string{"HOME": l.home, "USER": l.user, "XDG_RUNTIME_DIR": l.runtimeDir}
	if err := checkCwd(cwd, l.home); err != nil {
		return err
	}
	l.project = projectRoot(cwd)
	// The work tree is bound read-write whole, so it gets the same checks
	// (a git repo in ~ would otherwise bind all of the host home).
	if err := checkCwd(l.project, l.home); err != nil {
		return fmt.Errorf("%s is in the git work tree %s: %w", cwd, l.project, err)
	}
	return nil
}

// makeVolume makes the project's dir in the state dir: its home volume and
// what the host keeps for it.
func (l *launcher) makeVolume() error {
	stateDir := os.Getenv("SANDBOX_STATE_DIR")
	if stateDir == "" {
		stateDir = l.cfg.StateDir
	}
	if stateDir != "" {
		stateDir = os.Expand(stateDir, func(name string) string {
			if v, ok := l.vars[name]; ok {
				return v
			}
			return os.Getenv(name)
		})
	} else {
		stateDir = filepath.Join(xdgDir("XDG_DATA_HOME", l.home, ".local/share"), "sandbox")
	}
	stateDir = realpath(stateDir)
	if err := checkOutside(l.cwd, stateDir); err != nil {
		return err
	}
	if err := checkOutside(l.project, stateDir); err != nil {
		return fmt.Errorf("%s is in the git work tree %s: %w", l.cwd, l.project, err)
	}
	l.volumeDir = filepath.Join(stateDir, volumeName(l.project))
	// Private: it holds the project's tokens and secrets.
	if err := os.MkdirAll(l.volumeDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(l.volumeDir, 0o700); err != nil {
		return err
	}
	return os.MkdirAll(l.homeVolume(), 0o755)
}

// homeVolume is the per-project persistent $HOME, nested at $HOME's own path
// inside the volume dir, so secrets.sqlite3 and exchange/ next to it stay
// out of reach. Only ever written from inside the sandbox (init) -
// the sandbox can plant symlinks in it, which host-side writes would
// follow.
func (l *launcher) homeVolume() string {
	return l.volumeDir + l.home
}

func (l *launcher) startGuards(ctx context.Context, g *guards, a *bwrapArgs, prof profile) error {
	gc := l.cfg.Guards
	if gc.SSHAgent.Enable {
		if err := g.sshAgent(ctx, a, l.vars); err != nil {
			return err
		}
		// The hosts the host already trusts, where ssh reads system-wide
		// config; the volume's own ~/.ssh/known_hosts stays writable.
		a.add("--ro-bind-try", l.home+"/.ssh/known_hosts", "/etc/ssh/ssh_known_hosts")
	}
	if gc.SecretService {
		if err := g.secretService(ctx, a, l.volumeDir, l.runtimeDir); err != nil {
			return err
		}
	}
	if gc.GitHub {
		token := ""
		if command := prof.GitHubTokenCommand; command != "" {
			var err error
			if token, err = l.runTokenCommand(ctx, "guards.github.tokenCommand", command); err != nil {
				return err
			}
		}
		if err := g.github(ctx, a, token); err != nil {
			fmt.Fprintf(os.Stderr, "sandbox: %v - gh inside has no API access\n", err)
		}
	}
	if gc.Forgejo {
		commands, err := forgejoHosts("guards.forgejo.tokenCommands", prof.ForgejoTokenCommands)
		if err != nil {
			return err
		}
		hostTokens := map[string]string{}
		for host, command := range commands {
			if hostTokens[host], err = l.runTokenCommand(ctx, "guards.forgejo.tokenCommands."+host, command); err != nil {
				return err
			}
		}
		if err := g.forgejo(ctx, a, hostTokens); err != nil {
			return err
		}
	}
	if err := g.caBundle(a, l.runtimeDir); err != nil {
		return err
	}
	if prof.ClaudeAPIKey {
		if err := g.claudeAPI(ctx, a, l.volumeDir, l.runtimeDir); err != nil {
			return err
		}
	}
	if gc.OpenURL {
		if err := g.openURL(ctx, a, l.runtimeDir); err != nil {
			return err
		}
	}
	return nil
}

// resolvConf mounts a resolv.conf for inside over the host's when the
// host's resolver is out of reach there (see dnsForward); the resolver to
// forward to, or "".
func (l *launcher) resolvConf(g *guards, a *bwrapArgs) (string, error) {
	path := l.cfg.ResolvConf
	if path == "" {
		path = "/etc/resolv.conf"
	}
	data, _ := os.ReadFile(path)
	resolver, text := dnsForward(string(data))
	if resolver == "" {
		return "", nil
	}
	dir, err := g.tempdir()
	if err != nil {
		return "", err
	}
	inside := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(inside, []byte(text), 0o644); err != nil {
		return "", err
	}
	// Over the host's, which hostEtc binds.
	a.roBind(inside, "/etc/resolv.conf")
	return resolver, nil
}

// initArgs runs sandbox-bin init, which links the nix profile and home-manager
// generation into the volume, then execs the login shell; --login reads
// .bash_profile/.profile, and the exec trick runs a given command after
// that same chain.
func (l *launcher) initArgs(a *bwrapArgs) {
	a.add("--chdir", l.cwd, l.self, "init")
	for _, p := range []struct {
		on   bool
		path string
	}{
		{l.cfg.Init.NixProfile, l.home + "/.nix-profile"},
		{l.cfg.Init.HomeManager, l.home + "/.local/state/nix/profiles/home-manager"},
	} {
		if p.on && lexists(p.path) {
			a.add(realpath(p.path))
		} else {
			a.add("")
		}
	}
	if len(l.command) > 0 {
		a.add(l.cfg.Tools.Shell, "--login", "-c", `exec "$@"`, "bash")
		a.add(l.command...)
	} else {
		a.add(l.cfg.Tools.Shell, "--login")
	}
}

// selectProfile is the highest-priority profile matching cwd (by path
// prefix) or the project (by a file in its root), else the default one.
func selectProfile(cfg *config, cwd, project string, vars map[string]string) profile {
	var best *profile
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		matches := slices.ContainsFunc(p.Paths, func(path string) bool {
			return within(cwd, expand(path, vars))
		}) || slices.ContainsFunc(p.ProjectFiles, func(f string) bool {
			return lexists(filepath.Join(project, f))
		})
		if matches && (best == nil || p.Priority > best.Priority) {
			best = p
		}
	}
	if best == nil {
		return cfg.Default
	}
	return *best
}

// runSandbox runs argv in the foreground; its exit status.
//
// With popups (the guards' socket, see popuprelay), argv runs on a pty of
// the launcher's, which shows the guards' popups. Without, it runs on the
// launcher's own terminal (or none), and the guards ask no one.
//
// A SIGINT reaches the whole foreground process group anyway, so it's only
// kept from killing the launcher before cleanup; SIGTERM and SIGHUP are
// passed on.
func runSandbox(argv []string, popups *net.UnixListener, signals <-chan os.Signal) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	var err error
	if popups != nil {
		err = popuprelay.Run(cmd, popups, signals)
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err = cmd.Start(); err != nil {
			return 0, err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
	wait:
		for {
			select {
			case sig := <-signals:
				if sig != syscall.SIGINT {
					_ = cmd.Process.Signal(sig)
				}
			case err = <-done:
				break wait
			}
		}
	}
	return exitStatus(cmd, err)
}

// exitStatus is the status a shell would give cmd's exit: 128+N for a
// signal.
func exitStatus(cmd *exec.Cmd, err error) (int, error) {
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return 0, err
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return cmd.ProcessState.ExitCode(), nil
}
