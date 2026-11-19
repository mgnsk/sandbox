// Package launcher is the sandbox launcher: it runs a command (default: a
// login bash) in a per-project sandbox.
//
//	sandbox CONFIG.json [OPTIONS] [--] [COMMAND...]
//
// bwrap + pasta + seccomp, with guard proxies on the host for ssh-agent, a
// Secret Service, the GitHub, Forgejo and Claude APIs and opening URLs. See
// SECURITY.md for the threat model; the reasoning for individual flags is
// next to them here.
//
// Everything it runs - bwrap, pasta, the guards, the environment inside -
// comes from store paths in CONFIG.json or from this binary, never from the
// host's PATH. The guards and sandbox-init are this binary under their own
// names, next to it.
//
// Without a config of its own (the flake's default package), it runs with
// ~/.config/sandbox/config.nix when that exists: a module like any other
// sandbox config, built on the host with nix-build and cached until a file
// in ~/.config/sandbox or the sandbox itself changes.
//
// A project's sandbox.nix adds to the selected profile. It is evaluated
// inside a sandbox of the project, and what it asks for beyond the inside
// (binds, host ports) is shown on the terminal for approval first.
//
// Options:
//
//	--reload             evaluate sandbox.nix and ~/.config/sandbox/config.nix
//	                     again, even if they are unchanged
//	--no-project-config  ignore sandbox.nix
//	--claude-api-key     set this project's Claude API key and exit (when
//	                     guards.claudeApiKey.enable is on for its profile);
//	                     running sandboxes pick it up
//	--gh-token           set this project's GitHub token and exit
//	--fj-token HOST      set this project's token for a Forgejo host and exit
package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mgnsk/sandbox/internal/popuprelay"
)

type launcher struct {
	self string // This binary, which the guards and sandbox-init are too.

	// Set while a subprocess runs that a Ctrl-C interrupts (nix-build, the
	// evaluation of sandbox.nix); interrupted records one came.
	inSubprocess atomic.Bool
	interrupted  atomic.Bool

	mu       sync.Mutex
	onSignal func(os.Signal)
}

func getwd() (string, error) {
	// Physical, not $PWD: a symlink to ~ mustn't slip past the checks.
	return syscall.Getwd()
}

// Main runs the launcher with argv; its exit status.
func Main(argv []string) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
		return 1
	}
	l := &launcher{self: self}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	// Until the guards start, nothing to clean up: as the signal would.
	l.setOnSignal(func(sig os.Signal) {
		if sig == syscall.SIGINT && l.inSubprocess.Load() {
			l.interrupted.Store(true)
			return
		}
		signal.Reset(sig)
		_ = syscall.Kill(os.Getpid(), sig.(syscall.Signal))
	})
	go func() {
		for sig := range signals {
			l.mu.Lock()
			handle := l.onSignal
			l.mu.Unlock()
			handle(sig)
		}
	}()

	code, err := l.main(argv)
	var serr *sandboxError
	if errors.As(err, &serr) {
		fmt.Fprintf(os.Stderr, "sandbox: %s\n", serr.msg)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
		return 1
	}
	// As a negative status (killed by a signal) from Python's sys.exit.
	return code & 0xff
}

func (l *launcher) setOnSignal(f func(os.Signal)) {
	l.mu.Lock()
	l.onSignal = f
	l.mu.Unlock()
}

// selectProfile is the highest-priority profile matching cwd (by path
// prefix) or the project (by a file in its root), else the default one.
func selectProfile(cfg *config, cwd, project string, variables map[string]string) profile {
	var best *profile
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		matches := false
		for _, path := range p.Paths {
			if strings.HasPrefix(cwd+"/", strings.TrimRight(expand(path, variables), "/")+"/") {
				matches = true
			}
		}
		for _, f := range p.ProjectFiles {
			if lexists(filepath.Join(project, f)) {
				matches = true
			}
		}
		if matches && (best == nil || p.Priority > best.Priority) {
			best = p
		}
	}
	if best == nil {
		return cfg.Default
	}
	return *best
}

// upgradeNotice suggests an upgrade once the installed flake is `days` old.
func upgradeNotice(released, days *float64, now time.Time) string {
	if released == nil || days == nil || *released == 0 || *days == 0 {
		return ""
	}
	age := int(math.Floor((float64(now.UnixNano())/1e9 - *released) / 86400))
	if float64(age) < *days {
		return ""
	}
	return fmt.Sprintf("this sandbox is %d days old; `nix profile upgrade sandbox` updates "+
		"it and the tools inside (upgradeNotice.days = 0 turns this off)", age)
}

// insideEnv is the environment inside: passed-through host vars, then the
// profile's own (PATH included), with $HOME etc. expanded.
func insideEnv(cfg *config, p profile, variables map[string]string) orderedEnv {
	env := orderedEnv{
		{"HOME", variables["HOME"]},
		{"USER", variables["USER"]},
		{"LOGNAME", variables["USER"]},
		{"XDG_RUNTIME_DIR", variables["XDG_RUNTIME_DIR"]},
	}
	for _, name := range cfg.PassEnv {
		if value, ok := os.LookupEnv(name); ok {
			env.set(name, value)
		}
	}
	for _, v := range p.Env {
		env.set(v.name, expand(v.value, variables))
	}
	return env
}

// bindArgs are the bwrap args for the profile's extra binds and the
// project.
func bindArgs(binds []bind, variables map[string]string, project string) []string {
	var args []string
	for _, b := range binds {
		src := realpath(expand(b.Src, variables))
		dst := src
		if b.Dst != nil && *b.Dst != "" {
			dst = expand(*b.Dst, variables)
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
		args = append(args, flag, src, dst)
		if b.HideGit && isDir(filepath.Join(src, ".git")) {
			// Its history, with whatever was ever committed and removed
			// again, is none of another project's business.
			args = append(args, "--tmpfs", filepath.Join(dst, ".git"))
		}
	}
	// The whole work tree rather than just $PWD, so starting in a
	// subdirectory still gets .git.
	return append(args, "--bind", project, project)
}

// baseArgs are the namespaces, environment and the filesystem every
// sandbox has.
func baseArgs(cfg *config, env orderedEnv) []string {
	args := []string{
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
	for _, v := range env {
		args = append(args, "--setenv", v.name, v.value)
	}
	args = append(args,
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--tmpfs", env.get("XDG_RUNTIME_DIR"),
		// Read-only is enough for builds to land in the host store: the
		// daemon socket stays connectable on a ro mount, and the host's
		// nix-daemon does the actual store writes.
		"--ro-bind", "/nix", "/nix",
		// Nothing of the host's /usr, /bin or /lib: the few fixed paths
		// programs expect, from the store.
		"--ro-bind", cfg.FHS.Bin, "/bin",
		"--ro-bind", cfg.FHS.UsrBin, "/usr/bin",
		"--ro-bind", cfg.FHS.NixLd, cfg.FHS.LdPath,
		"--ro-bind", cfg.FHS.SSL, "/etc/ssl",
	)
	for _, path := range cfg.HostEtc {
		args = append(args, "--ro-bind-try", path, path)
	}
	return args
}

func readConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (l *launcher) main(argv []string) (int, error) {
	if len(argv) < 2 {
		return 0, errorf("usage: sandbox CONFIG.json [OPTIONS] [--] [COMMAND...]")
	}
	configPath := argv[1]
	cfg, err := readConfig(configPath)
	if err != nil {
		return 0, err
	}
	opts, command, err := parseOptions(argv[2:])
	if err != nil {
		return 0, err
	}

	// Physical, so a symlink to ~ can't slip past the checks, and the binds
	// name the real path.
	cwd, err := getwd()
	if err != nil {
		return 0, err
	}
	_ = os.Chdir(cwd)
	homeEnv, ok := os.LookupEnv("HOME")
	if !ok {
		return 0, errorf("HOME is not set")
	}
	home := realpath(homeEnv)
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}
	if user == "" {
		user = strconv.Itoa(os.Getuid())
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	variables := map[string]string{"HOME": home, "USER": user, "XDG_RUNTIME_DIR": runtimeDir}
	if err := checkCwd(cwd, home); err != nil {
		return 0, err
	}
	project := projectRoot(cwd)

	// The work tree is bound read-write whole, so it gets the same checks
	// (a git repo in ~ would otherwise bind all of the host home).
	inWorkTree := func(err error) error {
		if err != nil && project != cwd {
			return errorf("%s is in the git work tree %s: %s", cwd, project, err.Error())
		}
		return nil
	}
	if err := inWorkTree(checkCwd(project, home)); err != nil {
		return 0, err
	}
	// The installed package's age; a config built from config.nix has none.
	released := cfg.Released
	configPath, cfg, err = l.userConfig(cfg, configPath, home, project, opts.reload)
	if err != nil {
		return 0, err
	}
	if notice := upgradeNotice(released, cfg.UpgradeNoticeDays, time.Now()); notice != "" && os.Getenv(quietEnv) == "" {
		fmt.Fprintf(os.Stderr, "sandbox: %s\n", notice)
	}

	stateDir := os.Getenv("SANDBOX_STATE_DIR")
	if stateDir == "" && cfg.StateDir != nil {
		stateDir = *cfg.StateDir
	}
	if stateDir != "" {
		vars := map[string]string{}
		for _, kv := range os.Environ() {
			if k, v, ok := cutEnv(kv); ok {
				vars[k] = v
			}
		}
		for k, v := range variables {
			vars[k] = v
		}
		stateDir = expand(stateDir, vars)
	} else {
		base := os.Getenv("XDG_DATA_HOME")
		if base == "" {
			base = home + "/.local/share"
		}
		stateDir = filepath.Join(base, "sandbox")
	}
	stateDir = realpath(stateDir)
	if err := checkOutside(cwd, stateDir); err != nil {
		return 0, err
	}
	if err := inWorkTree(checkOutside(project, stateDir)); err != nil {
		return 0, err
	}
	volumeDir := filepath.Join(stateDir, volumeName(project))
	// Per-project persistent $HOME, nested at $HOME's own path inside the
	// volume dir, so secrets.sqlite3 and exchange/ next to it stay out of
	// reach. Only ever written from inside the sandbox (sandbox-init) - the
	// sandbox can plant symlinks in it, which host-side writes would
	// follow.
	homeVolume := volumeDir + home
	if err := os.MkdirAll(homeVolume, 0o777); err != nil {
		return 0, err
	}

	prof := selectProfile(cfg, cwd, project, variables)
	// Per profile: Claude Code on an API key here, or logged in inside.
	claudeAPI := prof.ClaudeAPIKey
	switch {
	case opts.claudeAPIKey:
		if !claudeAPI {
			name := "default"
			if prof.Name != nil {
				name = *prof.Name
			}
			return 0, errorf("--claude-api-key needs guards.claudeApiKey.enable for this project's profile (%s)", name)
		}
		_, err := claudeAPIKey(volumeDir, true)
		return 0, err
	case opts.ghToken:
		if !cfg.Guards.GitHub {
			return 0, errorf("--gh-token needs guards.github.enable")
		}
		return 0, setGitHubToken(volumeDir)
	case opts.fjToken != "":
		if !cfg.Guards.Forgejo {
			return 0, errorf("--fj-token needs guards.forgejo.enable")
		}
		return 0, setForgejoToken(volumeDir, opts.fjToken)
	}
	hostPorts := cfg.HostPorts
	if opts.projectConfig && lexists(filepath.Join(project, projectFileName)) {
		base := ""
		if prof.ClaudeDir != nil {
			base = *prof.ClaudeDir
		}
		m, err := l.projectManifest(cfg, configPath, project, volumeDir, base, opts.reload)
		if err != nil {
			return 0, err
		}
		if err := approveProject(m, volumeDir, filepath.Join(project, projectFileName)); err != nil {
			return 0, err
		}
		prof = applyProject(prof, m)
		hostPorts = append(append([]string{}, hostPorts...), m.HostPorts...)
		if len(command) == 0 && len(m.Command) > 0 {
			command = m.Command
		}
	}
	tcp, udp, err := parseHostPorts(hostPortSpecs(hostPorts))
	if err != nil {
		return 0, err
	}
	claudeKeyFile := ""
	if claudeAPI {
		if claudeKeyFile, err = claudeAPIKey(volumeDir, false); err != nil {
			return 0, err
		}
	}

	if unix.Access(cfg.Seccomp, unix.R_OK) != nil {
		return 0, errorf("missing seccomp filter %s", cfg.Seccomp)
	}

	env := insideEnv(cfg, prof, variables)
	args := baseArgs(cfg, env)
	// Must precede every mount under $HOME - bwrap layers mounts in argv
	// order, so those narrower binds shadow the volume, not the other way
	// round.
	args = append(args, "--bind", homeVolume, home)

	g := newGuards(l.self, cfg)
	defer g.close()
	var listener *net.UnixListener
	closeAll := func() {
		if listener != nil {
			listener.Close()
		}
		g.close()
	}
	// Cleanup on a signal arriving during startup too.
	l.setOnSignal(func(sig os.Signal) {
		if sig == syscall.SIGINT && l.inSubprocess.Load() {
			l.interrupted.Store(true)
			return
		}
		closeAll()
		os.Exit(128 + int(sig.(syscall.Signal)))
	})

	// Before the guards start, so they get its path.
	if popuprelay.Usable() {
		dir, err := g.tempdir()
		if err != nil {
			return 0, err
		}
		path := filepath.Join(dir, "popup.sock")
		if listener, err = popuprelay.Listen(path); err != nil {
			return 0, err
		}
		defer listener.Close()
		g.setEnv(popupEnv, path)
	}

	add := func(more []string, err error) error {
		args = append(args, more...)
		return err
	}
	gc := cfg.Guards
	if gc.SSHAgent.Enable {
		if err := add(g.sshAgentArgs(variables)); err != nil {
			return 0, err
		}
		// The hosts the host already trusts, where ssh reads system-wide
		// config; the volume's own ~/.ssh/known_hosts stays writable.
		args = append(args, "--ro-bind-try", home+"/.ssh/known_hosts", "/etc/ssh/ssh_known_hosts")
	}
	if gc.SecretService {
		if err := add(g.secretServiceArgs(volumeDir, runtimeDir)); err != nil {
			return 0, err
		}
	}
	if gc.GitHub {
		args = append(args, g.githubArgs(volumeDir)...)
	}
	if gc.Forgejo {
		if err := add(g.forgejoArgs(volumeDir)); err != nil {
			return 0, err
		}
	}
	if err := add(g.caBundleArgs(runtimeDir)); err != nil {
		return 0, err
	}
	tcp = append(tcp, g.tcpPorts...)
	if claudeAPI {
		if err := add(g.claudeAPIArgs(claudeKeyFile, runtimeDir)); err != nil {
			return 0, err
		}
	}
	if gc.OpenURL {
		if err := add(g.openURLArgs(runtimeDir)); err != nil {
			return 0, err
		}
	}

	// Claude Code's managed settings, memory and MCP servers: managed
	// settings outrank user/project/local ones, so ~/.claude in the volume
	// can't override them.
	if prof.ClaudeDir != nil && *prof.ClaudeDir != "" {
		args = append(args, "--ro-bind", *prof.ClaudeDir, "/etc/claude-code")
	}

	resolvPath := "/etc/resolv.conf"
	if cfg.ResolvConf != nil {
		resolvPath = *cfg.ResolvConf
	}
	dnsResolver, resolvConf := dnsForward(readResolvConf(resolvPath))
	if dnsResolver != "" {
		dir, err := g.tempdir()
		if err != nil {
			return 0, err
		}
		path := filepath.Join(dir, "resolv.conf")
		if err := os.WriteFile(path, []byte(resolvConf), 0o666); err != nil {
			return 0, err
		}
		// Mounted over the host's, bound in baseArgs.
		args = append(args, "--ro-bind", path, "/etc/resolv.conf")
	}

	if err := add(exchangeArgs(volumeDir)); err != nil {
		return 0, err
	}
	args = append(args, bindArgs(prof.Binds, variables, project)...)

	// sandbox-init links the nix profile and home-manager generation into
	// the volume, then execs the login shell; --login reads
	// .bash_profile/.profile, and the exec trick runs a given command after
	// that same chain.
	args = append(args, "--chdir", cwd, filepath.Join(filepath.Dir(l.self), "sandbox-init"))
	for _, p := range []struct {
		on   bool
		path string
	}{
		{cfg.Init.NixProfile, home + "/.nix-profile"},
		{cfg.Init.HomeManager, home + "/.local/state/nix/profiles/home-manager"},
	} {
		if p.on && lexists(p.path) {
			args = append(args, realpath(p.path))
		} else {
			args = append(args, "")
		}
	}
	shell := cfg.Tools.Shell
	if len(command) > 0 {
		args = append(args, shell, "--login", "-c", `exec "$@"`, "bash")
		args = append(args, command...)
	} else {
		args = append(args, shell, "--login")
	}

	addrs, err := hostAddresses(cfg.Tools.IP)
	if err != nil {
		return 0, err
	}
	return l.run(pastaArgv(cfg, tcp, udp, addrs, args, dnsResolver), listener)
}

// run runs argv in the foreground; its exit status.
//
// With popups (the guards' socket, see popuprelay), argv runs on a pty of
// the launcher's, which shows the guards' popups. Without, it runs on the
// launcher's own terminal (or none), and the guards ask no one.
//
// SIGINT reaches the whole foreground process group anyway, so it's only
// kept from killing the launcher before cleanup. A handler rather than
// ignoring it: an ignored signal stays ignored across exec.
func (l *launcher) run(argv []string, popups *net.UnixListener) (int, error) {
	if popups != nil {
		relay := popuprelay.New(popups)
		l.setOnSignal(relay.Signal)
		return relay.Run(argv)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	l.setOnSignal(func(sig os.Signal) {
		if sig != syscall.SIGINT {
			_ = cmd.Process.Signal(sig)
		}
	})
	_ = cmd.Wait()
	return status(cmd.ProcessState), nil
}

func cutEnv(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return "", "", false
}
