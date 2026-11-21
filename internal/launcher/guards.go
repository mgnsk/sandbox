package launcher

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/popup"
	"github.com/mgnsk/sandbox/internal/popuprelay"
	"github.com/mgnsk/sandbox/internal/waylandguard"
)

const (
	// How long a guard has to say it's ready.
	startTimeout = 10 * time.Second
	// How long a guard has to exit after SIGTERM, before it's killed.
	stopTimeout = 2 * time.Second
)

// guards are the host-side guard processes of a sandbox and their temp
// dirs, torn down on close.
//
// An "always" answer to any guard's popup lives in that guard's memory, so
// it ends with this sandbox.
type guards struct {
	self string // This binary, which the guards are too.
	cfg  *config
	env  []string

	procs []*proc
	dirs  []string
	// Where the temp dirs go: the user's runtime dir, which is theirs
	// alone and which no project can be in (see checkSystem).
	runtimeDir string
	popups     *net.UnixListener // Where the guards ask, if anywhere.
	// The sandbox has a Wayland display: programs inside may ask from a
	// window, away from the terminal.
	display bool

	// Host loopback ports pasta maps in (-T), and CA certificates clients
	// inside trust, from the HTTPS-intercepting guards.
	tcpPorts []string
	caCerts  []string
}

// proc is a started guard, whose exit closes done.
type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func newGuards(self string, cfg *config) *guards {
	g := &guards{self: self, cfg: cfg}
	// xdg-open from the store first; the host's PATH after, for what
	// xdg-open hands URLs to (the browser).
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PATH=") {
			g.env = append(g.env, kv)
		}
	}
	// No empty entry, which is the working directory.
	path := cfg.HostPath
	if host := os.Getenv("PATH"); host != "" {
		path += ":" + host
	}
	g.env = append(g.env, "PATH="+path)
	return g
}

// listenPopups opens the launcher's popup socket, which the guards started
// after this ask at.
func (g *guards) listenPopups() error {
	dir, err := g.tempdir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "popup.sock")
	if g.popups, err = popuprelay.Listen(path); err != nil {
		return err
	}
	g.env = append(g.env, popup.Env+"="+path)
	return nil
}

// tempdir makes a private directory that goes with the sandbox, for the
// guards' sockets and the files the launcher writes for inside.
func (g *guards) tempdir() (string, error) {
	dir, err := os.MkdirTemp(g.runtimeDir, "sandbox-")
	if err != nil && g.runtimeDir != "" {
		// A host without a runtime dir.
		dir, err = os.MkdirTemp("", "sandbox-")
	}
	if err == nil {
		g.dirs = append(g.dirs, dir)
	}
	return dir, err
}

// argsFile writes bwrap's arguments to a file it reads them from (--args),
// for what they hold: the API guards' secrets, which on a command line any
// user of the host could read.
func (g *guards) argsFile(a bwrapArgs) (string, error) {
	dir, err := g.tempdir()
	if err != nil {
		return "", err
	}
	var data []byte
	for _, arg := range a {
		data = append(append(data, arg...), 0)
	}
	path := filepath.Join(dir, "bwrap-args")
	return path, os.WriteFile(path, data, 0o600)
}

// process is a program started with the guards: a guard, or what one needs
// (its bus, its proxy).
type process struct {
	// Names it in errors.
	name string
	argv []string
	// The guards' environment when nil.
	env []string
	// What it serves on, passed in as guard.ListenerFD; nil for none.
	listener interface{ File() (*os.File, error) }
	// Handed over on guard.SecretFD, over a pipe - never on disk, argv or
	// the environment; nil for none.
	secret []byte
}

// start runs p with the launcher's stdio and waits for its ready line (see
// package guard), which it returns. Failing here names the guard, rather
// than leaving bwrap to trip over a missing socket.
func (g *guards) start(ctx context.Context, p process) ([]byte, error) {
	name, argv, env, secret := p.name, p.argv, p.env, p.secret
	if env == nil {
		env = g.env
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	cmd := &exec.Cmd{
		Path: argv[0], Args: argv, Env: env,
		// From /, never the project: nothing the sandbox wrote there is
		// found by a guard or by what it runs (xdg-open, the browser).
		Dir:   "/",
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		ExtraFiles: []*os.File{w},
		// A launcher that's killed leaves no guard behind, holding a token.
		SysProcAttr: &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM},
	}
	if p.listener != nil {
		f, err := p.listener.File()
		if err != nil {
			w.Close()
			return nil, err
		}
		defer f.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	}
	var sw *os.File
	if secret != nil {
		sr, pw, err := os.Pipe()
		if err != nil {
			w.Close()
			return nil, err
		}
		defer sr.Close()
		sw = pw
		cmd.ExtraFiles = append(cmd.ExtraFiles, sr)
	}
	err = cmd.Start()
	w.Close()
	if sw != nil {
		// Small enough for the pipe's buffer, so this doesn't block.
		_, werr := sw.Write(secret)
		sw.Close()
		if err == nil && werr != nil {
			err = werr
		}
	}
	if err != nil {
		return nil, fmt.Errorf("can't start %s: %w", name, err)
	}
	started := &proc{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(started.done)
	}()
	g.procs = append(g.procs, started)

	ready := make(chan []byte, 1)
	go func() {
		line, _ := bufio.NewReader(r).ReadBytes('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if len(line) > 0 && line[len(line)-1] == '\n' {
			return line, nil
		}
		select {
		case <-started.done:
			return nil, fmt.Errorf("%s exited with status %d", name, cmd.ProcessState.ExitCode())
		case <-time.After(stopTimeout):
			return nil, fmt.Errorf("%s closed its ready pipe", name)
		}
	case <-time.After(startTimeout):
		return nil, fmt.Errorf("%s didn't start", name)
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

// program is the argv that runs the guard name: this binary's subcommand
// of that name.
func (g *guards) program(name string, args ...string) []string {
	return append([]string{g.self, name}, args...)
}

// unixGuard starts the guard name, with secret if any (see process), on a
// socket in a private dir of its own, bound in at inside. The socket file
// stays when the launcher closes its end, for the guard that serves on it.
func (g *guards) unixGuard(ctx context.Context, a *bwrapArgs, name, inside string, secret []byte, args ...string) error {
	dir, err := g.tempdir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, filepath.Base(inside))
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	defer ln.Close()
	if _, err := g.start(ctx, process{name: name, argv: g.program(name, args...), listener: ln, secret: secret}); err != nil {
		return err
	}
	a.bind(path, inside)
	return nil
}

// close stops the guards, the last started first: a guard may need one
// started before it (secret-service-guard its bus) until it's gone.
func (g *guards) close() {
	for _, p := range slices.Backward(g.procs) {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(stopTimeout):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	}
	if g.popups != nil {
		g.popups.Close()
	}
	for _, d := range g.dirs {
		_ = os.RemoveAll(d)
	}
}

// sshAgent: sandboxed processes only see this proxy's socket, never the
// real one - signatures other than commit signing with one of signingKeys
// (public keys) are gated behind a popup.
func (g *guards) sshAgent(ctx context.Context, a *bwrapArgs, vars map[string]string, signingKeys []string) error {
	cfg := g.cfg.Guards.SSHAgent
	upstream := os.Getenv("SSH_AUTH_SOCK")
	if cfg.Socket != "" {
		upstream = expand(cfg.Socket, vars)
	}
	if upstream == "" {
		fmt.Fprintln(os.Stderr, "sandbox: no ssh agent ($SSH_AUTH_SOCK unset), none inside")
		return nil
	}
	inside := expand(cfg.Path, vars)
	a.setenv("SSH_AUTH_SOCK", inside)
	return g.unixGuard(ctx, a, "ssh-agent-guard", inside, nil, upstream, strings.Join(signingKeys, "\n"))
}

const busConf = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=%s</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`

// secretService: a private, ephemeral D-Bus bus with a Secret Service that
// keeps the project's items in the host's, so credentials go through
// libsecret instead of plaintext files. Only the private bus is bound in,
// never the host's.
func (g *guards) secretService(ctx context.Context, a *bwrapArgs, hostBus, project, runtimeDir string) error {
	if hostBus == "" {
		return errors.New("guards.secretService: no host session bus ($DBUS_SESSION_BUS_ADDRESS unset)" +
			" for the host's Secret Service - set guards.secretService.enable = false to start without one")
	}
	dir, err := g.tempdir()
	if err != nil {
		return err
	}
	sock := filepath.Join(dir, "bus.sock")
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, busConf, sock), 0o600); err != nil {
		return err
	}
	// The bus first, which prints its address once it listens.
	address, err := g.start(ctx, process{name: "dbus-daemon", argv: []string{g.cfg.DBusDaemon,
		"--config-file=" + conf, "--nofork", "--nopidfile", "--print-address=" + strconv.Itoa(guard.ReadyFD),
	}})
	if err != nil {
		return err
	}
	argv := g.program("secret-service-guard", strings.TrimSpace(string(address)), hostBus, project)
	if _, err := g.start(ctx, process{name: "secret-service-guard", argv: argv}); err != nil {
		return err
	}
	inside := runtimeDir + "/bus"
	a.bind(sock, inside)
	a.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+inside)
	return nil
}

// httpsProxy starts an HTTPS-intercepting guard; its HTTPS_PROXY URL.
//
// It listens on a free port of the host's loopback, which pasta maps to the
// same port inside. The URL carries a per-launch secret the guard checks,
// since anything on the host's loopback can connect to that port. Its CA
// certificate (the key stays in the guard) goes into the bundle clients
// inside trust, see caBundle. The URL goes to the router (internal/router),
// which init starts inside and every client reaches the guards through.
func (g *guards) httpsProxy(ctx context.Context, name string, secret []byte) (string, error) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", err
	}
	defer ln.Close()
	line, err := g.start(ctx, process{name: name, argv: g.program(name), listener: ln, secret: secret})
	if err != nil {
		return "", err
	}
	var info apiproxy.Info
	if err := json.Unmarshal(line, &info); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	g.tcpPorts = append(g.tcpPorts, port)
	g.caCerts = append(g.caCerts, info.CA)
	return "http://sandbox:" + info.Secret + "@127.0.0.1:" + port, nil
}

// github: gh inside (any gh, through the router) has just a placeholder
// token; gh-api-proxy, out here, intercepts its requests, swaps in token -
// from the token command, held only in its memory - and gates
// writes behind a popup. Never a per-sandbox OAuth login: those hit
// GitHub's cap on simultaneously valid tokens.
func (g *guards) github(ctx context.Context, a *bwrapArgs, token string) error {
	url, err := g.httpsProxy(ctx, "gh-api-proxy", []byte(token))
	if err != nil {
		return err
	}
	a.setenv("SANDBOX_GH_PROXY", url)
	// Only so gh considers itself logged in; never a real credential.
	a.setenv("GH_TOKEN", "sandbox-placeholder")
	return nil
}

// forgejo: the same for fj: forgejo-api-proxy adds hostTokens' token for
// each host, from the token commands, held only in its memory.
func (g *guards) forgejo(ctx context.Context, a *bwrapArgs, hostTokens map[string]string) error {
	secret, err := json.Marshal(hostTokens)
	if err != nil {
		return err
	}
	url, err := g.httpsProxy(ctx, "forgejo-api-proxy", secret)
	if err != nil {
		return err
	}
	a.setenv("SANDBOX_FJ_PROXY", url)
	return nil
}

// caBundle: the system CA bundle plus the HTTPS-intercepting guards' CAs,
// as SANDBOX_CA_FILE, which init makes every client's SSL_CERT_FILE (and
// NIX_SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE). Only connections the router
// sends to a guard meet these CAs' certificates. It is also the system
// bundle's path inside, for what goes by that instead: nix's own nix.sh,
// sourced from a user's shell files, sets NIX_SSL_CERT_FILE to it whatever
// it was, and some programs read it by path.
func (g *guards) caBundle(a *bwrapArgs, runtimeDir string) error {
	if len(g.caCerts) == 0 {
		return nil
	}
	system, err := os.ReadFile(filepath.Join(g.cfg.FHS.SSL, "certs", "ca-bundle.crt"))
	if err != nil {
		return err
	}
	dir, err := g.tempdir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "ca-bundle.pem")
	bundle := strings.Join(append([]string{strings.TrimRight(string(system), "\n")}, g.caCerts...), "\n")
	if err := os.WriteFile(path, []byte(bundle), 0o644); err != nil {
		return err
	}
	inside := runtimeDir + "/sandbox-ca.pem"
	a.roBind(path, inside)
	a.roBind(path, "/etc/ssl/certs/ca-bundle.crt")
	a.setenv("SANDBOX_CA_FILE", inside)
	return nil
}

// claudeAPI: Claude Code inside sends its API requests as plain HTTP over a
// socket to claude-api-proxy, which adds key - from the key command, held
// only in its memory; the managed apiKeyHelper gives it a placeholder key.
func (g *guards) claudeAPI(ctx context.Context, a *bwrapArgs, key, runtimeDir string) error {
	inside := runtimeDir + "/claude-api.sock"
	a.setenv("ANTHROPIC_UNIX_SOCKET", inside)
	// http: plain requests on the socket, which the proxy can read.
	a.setenv("ANTHROPIC_BASE_URL", "http://api.anthropic.com")
	return g.unixGuard(ctx, a, "claude-api-proxy", inside, []byte(key))
}

// openURL: no display in here, so xdg-open (/usr/bin/xdg-open, the shim)
// hands http(s) URLs to open-url-guard, which opens them in the host's
// browser behind a popup.
func (g *guards) openURL(ctx context.Context, a *bwrapArgs, runtimeDir string) error {
	// BROWSER because Python's webbrowser doesn't try xdg-open without a
	// display variable, and npm's open honors it when it can't detect a
	// desktop.
	a.setenv("BROWSER", "/usr/bin/xdg-open")
	return g.unixGuard(ctx, a, "open-url-guard", runtimeDir+"/open-url.sock", nil)
}

// wayland: windows on the host's display, through wl-veil: a proxy that
// passes only the globals named on to clients inside, never the real
// socket, which gives any client whatever the compositor offers - on
// wlroots compositors the screen's contents, the clipboard at any time and
// synthetic input.
//
// wl-veil listens at the first free wayland-N of its $XDG_RUNTIME_DIR - a
// dir of its own here, so that's a path only the launcher knows - and
// serves for as long as the program it starts runs: wayland-guard, which
// reports the socket's name.
func (g *guards) wayland(ctx context.Context, a *bwrapArgs, runtimeDir string, globals []string) error {
	display := os.Getenv("WAYLAND_DISPLAY")
	if display == "" {
		fmt.Fprintln(os.Stderr, "sandbox: no Wayland display ($WAYLAND_DISPLAY unset), none inside")
		return nil
	}
	upstream := display
	if !filepath.IsAbs(upstream) {
		upstream = filepath.Join(runtimeDir, display)
	}
	if !exists(upstream) {
		fmt.Fprintf(os.Stderr, "sandbox: no Wayland display at %s, none inside\n", upstream)
		return nil
	}
	if len(globals) == 0 {
		return errors.New("guards.wayland.globals allows no global")
	}
	dir, err := g.tempdir()
	if err != nil {
		return err
	}
	var env []string
	for _, kv := range g.env {
		name, _, _ := strings.Cut(kv, "=")
		// WAYLAND_SOCKET would be a connection of the launcher's own; the
		// popup socket is for guards that ask, which this one never does.
		if !slices.Contains([]string{"XDG_RUNTIME_DIR", "WAYLAND_DISPLAY", "WAYLAND_SOCKET", "RUST_LOG", popup.Env}, name) {
			env = append(env, kv)
		}
	}
	// Errors only: wl-veil logs on the terminal the sandbox runs on.
	env = append(env, "XDG_RUNTIME_DIR="+dir, "WAYLAND_DISPLAY="+upstream, "RUST_LOG=error")
	argv := append([]string{g.cfg.Tools.WlVeil, "-i", "-f", strings.Join(globals, ","), "--"},
		g.program("wayland-guard")...)
	line, err := g.start(ctx, process{name: "wl-veil", argv: argv, env: env})
	if err != nil {
		return err
	}
	var info waylandguard.Info
	if err := json.Unmarshal(line, &info); err != nil {
		return fmt.Errorf("wl-veil: %w", err)
	}
	sock := filepath.Join(dir, info.Display)
	if filepath.Base(info.Display) != info.Display || !exists(sock) {
		return fmt.Errorf("wl-veil: no socket %q", info.Display)
	}
	a.bind(sock, runtimeDir+"/wayland-0")
	a.setenv("WAYLAND_DISPLAY", "wayland-0")
	g.display = true
	return nil
}
