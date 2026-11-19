package launcher

import (
	"bufio"
	"context"
	"encoding/json/v2"
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

	procs  []*proc
	dirs   []string
	popups *net.UnixListener // Where the guards ask, if anywhere.

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
	g.env = append(g.env, "PATH="+cfg.HostPath+":"+os.Getenv("PATH"))
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

func (g *guards) tempdir() (string, error) {
	dir, err := os.MkdirTemp("", "sandbox-")
	if err == nil {
		g.dirs = append(g.dirs, dir)
	}
	return dir, err
}

// start runs argv with the guards' environment and the launcher's stdio,
// with listener (if any) passed in, and waits for its ready line (see
// package guard). Failing here names the guard, rather than leaving bwrap to
// trip over a missing socket.
func (g *guards) start(ctx context.Context, name string, argv []string, listener *os.File, secret []byte) ([]byte, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	cmd := &exec.Cmd{
		Path: argv[0], Args: argv, Env: g.env,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		ExtraFiles: []*os.File{w},
	}
	if listener != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, listener)
	}
	// The guard's secret (guard.SecretFD), over a pipe: never on disk,
	// argv or the environment.
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
	p := &proc{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	g.procs = append(g.procs, p)

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
		case <-p.done:
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

// guard starts the guard name with a listener made for it.
func (g *guards) guard(ctx context.Context, name string, ln listener, args ...string) ([]byte, error) {
	return g.guardWithSecret(ctx, name, ln, nil, args...)
}

// guardWithSecret is guard, with secret handed over on guard.SecretFD.
func (g *guards) guardWithSecret(ctx context.Context, name string, ln listener, secret []byte, args ...string) ([]byte, error) {
	f, err := ln.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return g.start(ctx, name, g.program(name, args...), f, secret)
}

type listener interface {
	File() (*os.File, error)
	Close() error
}

// unixListener listens at path; the socket file stays when it's closed, for
// the guard that serves on it.
func unixListener(path string) (*net.UnixListener, error) {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err == nil {
		ln.SetUnlinkOnClose(false)
	}
	return ln, err
}

// unixGuard starts the guard name on a socket named sock in a temp dir of
// its own; the socket's path.
func (g *guards) unixGuard(ctx context.Context, name, sock string, args ...string) (string, error) {
	return g.unixGuardWithSecret(ctx, name, sock, nil, args...)
}

// unixGuardWithSecret is unixGuard, with secret handed over on
// guard.SecretFD.
func (g *guards) unixGuardWithSecret(ctx context.Context, name, sock string, secret []byte, args ...string) (string, error) {
	dir, err := g.tempdir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, sock)
	ln, err := unixListener(path)
	if err != nil {
		return "", err
	}
	defer ln.Close()
	_, err = g.guardWithSecret(ctx, name, ln, secret, args...)
	return path, err
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
// real one - signatures other than commit signing are gated behind a popup.
func (g *guards) sshAgent(ctx context.Context, a *bwrapArgs, vars map[string]string) error {
	cfg := g.cfg.Guards.SSHAgent
	upstream := os.Getenv("SSH_AUTH_SOCK")
	if cfg.Socket != "" {
		upstream = expand(cfg.Socket, vars)
	}
	if upstream == "" {
		fmt.Fprintln(os.Stderr, "sandbox: no ssh agent ($SSH_AUTH_SOCK unset), none inside")
		return nil
	}
	sock, err := g.unixGuard(ctx, "ssh-agent-guard", "agent.sock", upstream)
	if err != nil {
		return err
	}
	inside := expand(cfg.Path, vars)
	a.bind(sock, inside)
	a.setenv("SSH_AUTH_SOCK", inside)
	return nil
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

// secretService: a private, ephemeral D-Bus bus with a fake Secret Service,
// so credentials go through libsecret instead of plaintext files. The
// database itself is never bound in, only the socket, so it's only
// reachable through the API.
func (g *guards) secretService(ctx context.Context, a *bwrapArgs, volumeDir, runtimeDir string) error {
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
	address, err := g.start(ctx, "dbus-daemon", []string{g.cfg.DBusDaemon,
		"--config-file=" + conf, "--nofork", "--nopidfile", "--print-address=" + strconv.Itoa(guard.ReadyFD),
	}, nil, nil)
	if err != nil {
		return err
	}
	// The database holds credentials in plaintext, in the volume dir, which
	// only the user can enter.
	db := filepath.Join(volumeDir, "secrets.sqlite3")
	argv := g.program("secret-service-guard", strings.TrimSpace(string(address)), db)
	if _, err := g.start(ctx, "secret-service-guard", argv, nil, nil); err != nil {
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
	line, err := g.guardWithSecret(ctx, name, ln, secret)
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
// from the token command, held only in its memory; "" for none - and gates
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
// sends to a guard meet these CAs' certificates.
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
	a.setenv("SANDBOX_CA_FILE", inside)
	return nil
}

// claudeAPI: Claude Code inside sends its API requests as plain HTTP over a
// socket to claude-api-proxy, which adds key - from the key command, held
// only in its memory; the managed apiKeyHelper gives it a placeholder key.
func (g *guards) claudeAPI(ctx context.Context, a *bwrapArgs, key, runtimeDir string) error {
	sock, err := g.unixGuardWithSecret(ctx, "claude-api-proxy", "claude-api.sock", []byte(key))
	if err != nil {
		return err
	}
	inside := runtimeDir + "/claude-api.sock"
	a.bind(sock, inside)
	a.setenv("ANTHROPIC_UNIX_SOCKET", inside)
	// http: plain requests on the socket, which the proxy can read.
	a.setenv("ANTHROPIC_BASE_URL", "http://api.anthropic.com")
	return nil
}

// openURL: no display in here, so xdg-open (/usr/bin/xdg-open, the shim)
// hands http(s) URLs to open-url-guard, which opens them in the host's
// browser behind a popup.
func (g *guards) openURL(ctx context.Context, a *bwrapArgs, runtimeDir string) error {
	sock, err := g.unixGuard(ctx, "open-url-guard", "open-url.sock")
	if err != nil {
		return err
	}
	a.bind(sock, runtimeDir+"/open-url.sock")
	// BROWSER because Python's webbrowser doesn't try xdg-open without a
	// display variable, and npm's open honors it when it can't detect a
	// desktop.
	a.setenv("BROWSER", "/usr/bin/xdg-open")
	return nil
}
