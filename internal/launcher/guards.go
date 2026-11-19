package launcher

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mgnsk/sandbox/internal/popup"
)

// proc is a started process whose exit can be polled.
type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
	code int
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// status is the exit status as Python's returncode: -N for a signal.
func status(state *os.ProcessState) int {
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int(ws.Signal())
	}
	return state.ExitCode()
}

// guards are the host-side guard processes and their temp dirs, torn down
// on close.
//
// An "always" answer to any guard's popup lives in that guard's memory, so
// it ends with this sandbox.
type guards struct {
	self string
	cfg  *config

	mu     sync.Mutex
	closed bool
	procs  []*proc
	dirs   []string

	// Host loopback ports pasta maps in (-T), and CA certificates the gh/fj
	// wrappers trust, from the HTTPS-intercepting guards.
	tcpPorts []string
	caCerts  []string
	env      []string
}

func newGuards(self string, cfg *config) *guards {
	g := &guards{self: self, cfg: cfg}
	// gh, xdg-open, ... from the store first; the host's PATH after, for
	// what xdg-open hands URLs to (the browser).
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PATH=") && !strings.HasPrefix(kv, "PYTHONPATH=") {
			g.env = append(g.env, kv)
		}
	}
	g.env = append(g.env, "PATH="+cfg.HostPath+":"+os.Getenv("PATH"))
	return g
}

func (g *guards) setEnv(name, value string) {
	g.env = append(g.env, name+"="+value)
}

func (g *guards) tempdir() (string, error) {
	dir, err := os.MkdirTemp("", "sandbox-")
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	g.dirs = append(g.dirs, dir)
	g.mu.Unlock()
	return dir, nil
}

// start runs argv as a guard (argv[0] is what it runs as) with the guards'
// environment and the launcher's stdio.
func (g *guards) start(path string, argv []string) (*proc, error) {
	cmd := &exec.Cmd{Path: path, Args: argv, Env: g.env,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, errorf("stopping")
	}
	if err := cmd.Start(); err != nil {
		return nil, errorf("can't start %s: %v", argv[0], err)
	}
	p := &proc{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		p.code = status(cmd.ProcessState)
		close(p.done)
	}()
	g.procs = append(g.procs, p)
	return p, nil
}

// guard starts the guard name, which this binary runs as.
func (g *guards) guard(name string, args ...string) (*proc, error) {
	return g.start(g.self, append([]string{name}, args...))
}

// waitFor waits for p to create path. Failing here names the guard, rather
// than leaving bwrap to trip over a missing bind source.
func (g *guards) waitFor(path string, p *proc, what string) error {
	deadline := time.Now().Add(5 * time.Second)
	for !exists(path) {
		if p.exited() {
			return errorf("%s exited with status %d", what, p.code)
		}
		if time.Now().After(deadline) {
			return errorf("%s didn't start (%s missing)", what, path)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func (g *guards) close() {
	g.mu.Lock()
	g.closed = true
	procs, dirs := g.procs, g.dirs
	g.mu.Unlock()
	for _, p := range procs {
		if !p.exited() {
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
		}
	}
	for _, p := range procs {
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	}
	for _, d := range dirs {
		_ = os.RemoveAll(d)
	}
}

// sshAgentArgs: sandboxed processes only see this proxy's socket, never the
// real one - sign requests other than commit signing are gated behind a
// popup.
func (g *guards) sshAgentArgs(variables map[string]string) ([]string, error) {
	cfg := g.cfg.Guards.SSHAgent
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if cfg.Socket != nil && *cfg.Socket != "" {
		socketPath = expand(*cfg.Socket, variables)
	}
	if socketPath == "" {
		fmt.Fprintln(os.Stderr, "sandbox: no ssh agent ($SSH_AUTH_SOCK unset), none inside")
		return nil, nil
	}
	dir, err := g.tempdir()
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "agent.sock")
	p, err := g.guard("ssh-agent-guard", socketPath, sock)
	if err != nil {
		return nil, err
	}
	if err := g.waitFor(sock, p, "ssh-agent-guard"); err != nil {
		return nil, err
	}
	inside := expand(cfg.Path, variables)
	return []string{"--bind", sock, inside, "--setenv", "SSH_AUTH_SOCK", inside}, nil
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

// secretServiceArgs: a private, ephemeral D-Bus bus with a fake Secret
// Service, so credentials go through libsecret instead of plaintext files.
// The database itself is never bound in, only the socket, so it's only
// reachable through the API.
func (g *guards) secretServiceArgs(volumeDir, runtimeDir string) ([]string, error) {
	tmp, err := g.tempdir()
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(tmp, "bus.sock")
	conf := filepath.Join(tmp, "bus.conf")
	ready := filepath.Join(tmp, "ready")
	// The database holds credentials in plaintext; secret-service-guard
	// keeps the file itself at 0600, this keeps the directory around it as
	// private.
	if err := os.MkdirAll(volumeDir, 0o777); err != nil {
		return nil, err
	}
	if err := os.Chmod(volumeDir, 0o700); err != nil {
		return nil, err
	}
	db := filepath.Join(volumeDir, "secrets.sqlite3")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf(busConf, sock)), 0o666); err != nil {
		return nil, err
	}
	bus, err := g.start(g.cfg.DBusDaemon, []string{g.cfg.DBusDaemon,
		"--config-file=" + conf, "--nofork", "--nopidfile"})
	if err != nil {
		return nil, err
	}
	// The bus first: the guard connects to it as soon as it starts.
	if err := g.waitFor(sock, bus, "dbus-daemon"); err != nil {
		return nil, err
	}
	guard, err := g.guard("secret-service-guard", "unix:path="+sock, db, ready)
	if err != nil {
		return nil, err
	}
	if err := g.waitFor(ready, guard, "secret-service-guard"); err != nil {
		return nil, err
	}
	inside := runtimeDir + "/bus"
	return []string{"--bind", sock, inside, "--setenv", "DBUS_SESSION_BUS_ADDRESS", "unix:path=" + inside}, nil
}

// httpsProxy starts an HTTPS-intercepting guard; its HTTPS_PROXY URL once
// it's up.
//
// It listens on a free port of the host's loopback, which pasta maps to the
// same port inside. The URL carries a per-launch secret the guard checks,
// since anything on the host's loopback can connect to that port. Its CA
// certificate (the key stays in the guard) goes into the bundle the gh/fj
// wrappers trust, see caBundleArgs.
func (g *guards) httpsProxy(name string, args ...string) (string, error) {
	tmp, err := g.tempdir()
	if err != nil {
		return "", err
	}
	p, err := g.guard(name, append([]string{tmp}, args...)...)
	if err != nil {
		return "", err
	}
	infoPath := filepath.Join(tmp, "proxy.json")
	if err := g.waitFor(infoPath, p, name); err != nil {
		return "", err
	}
	var info struct {
		Port   int    `json:"port"`
		Secret string `json:"secret"`
	}
	data, err := os.ReadFile(infoPath)
	if err == nil {
		err = json.Unmarshal(data, &info)
	}
	if err != nil {
		return "", errorf("%s: bad %s: %v", name, infoPath, err)
	}
	ca, err := os.ReadFile(filepath.Join(tmp, "ca.pem"))
	if err != nil {
		return "", errorf("%s: %v", name, err)
	}
	port := strconv.Itoa(info.Port)
	g.tcpPorts = append(g.tcpPorts, port)
	g.caCerts = append(g.caCerts, string(ca))
	return "http://sandbox:" + info.Secret + "@127.0.0.1:" + port, nil
}

// githubArgs: gh inside (upstream gh, wrapped to use SANDBOX_GH_PROXY as
// its HTTPS_PROXY) has just a placeholder token; gh-api-proxy, out here,
// intercepts its requests, swaps in the real token - the project's
// (`sandbox --gh-token`) or else the host's - and gates writes behind a
// popup. Never a per-sandbox OAuth login: those hit GitHub's cap on
// simultaneously valid tokens.
func (g *guards) githubArgs(volumeDir string) []string {
	url, err := g.httpsProxy("gh-api-proxy", filepath.Join(volumeDir, githubTokenFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v - gh inside has no API access\n", err)
		return nil
	}
	return []string{
		"--setenv", "SANDBOX_GH_PROXY", url,
		// Only so gh considers itself logged in; never a real credential.
		"--setenv", "GH_TOKEN", "sandbox-placeholder",
	}
}

// forgejoArgs: the same for fj: forgejo-api-proxy adds the project's token
// for the host (`sandbox --fj-token`) or else the one the host's fj is
// logged in with, read per request, so no login is needed to start.
func (g *guards) forgejoArgs(volumeDir string) ([]string, error) {
	url, err := g.httpsProxy("forgejo-api-proxy", filepath.Join(volumeDir, forgejoTokensFile))
	if err != nil {
		return nil, err
	}
	return []string{"--setenv", "SANDBOX_FJ_PROXY", url}, nil
}

// caBundleArgs: the system CA bundle plus the HTTPS-intercepting guards'
// CAs, as SANDBOX_CA_FILE, which the gh/fj wrappers make their
// SSL_CERT_FILE. Nothing else inside trusts these CAs.
func (g *guards) caBundleArgs(runtimeDir string) ([]string, error) {
	if len(g.caCerts) == 0 {
		return nil, nil
	}
	system, err := os.ReadFile(filepath.Join(g.cfg.FHS.SSL, "certs", "ca-bundle.crt"))
	if err != nil {
		return nil, err
	}
	dir, err := g.tempdir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "ca-bundle.pem")
	parts := append([]string{strings.TrimRight(string(system), "\n")}, g.caCerts...)
	if err := os.WriteFile(path, []byte(strings.Join(parts, "\n")), 0o666); err != nil {
		return nil, err
	}
	inside := runtimeDir + "/sandbox-ca.pem"
	return []string{"--ro-bind", path, inside, "--setenv", "SANDBOX_CA_FILE", inside}, nil
}

// claudeAPIArgs: Claude Code inside sends its API requests as plain HTTP
// over a socket to claude-api-proxy, which adds the project's API key; the
// managed apiKeyHelper gives it a placeholder key.
func (g *guards) claudeAPIArgs(keyFile, runtimeDir string) ([]string, error) {
	inside := runtimeDir + "/claude-api.sock"
	dir, err := g.tempdir()
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "claude-api.sock")
	p, err := g.guard("claude-api-proxy", sock, keyFile)
	if err != nil {
		return nil, err
	}
	if err := g.waitFor(sock, p, "claude-api-proxy"); err != nil {
		return nil, err
	}
	return []string{
		"--bind", sock, inside,
		"--setenv", "ANTHROPIC_UNIX_SOCKET", inside,
		// http: plain requests on the socket, which the proxy can read.
		"--setenv", "ANTHROPIC_BASE_URL", "http://api.anthropic.com",
	}, nil
}

// openURLArgs: no display in here, so xdg-open (/usr/bin/xdg-open, the
// shim) hands http(s) URLs to open-url-guard, which opens them in the
// host's browser behind a popup.
func (g *guards) openURLArgs(runtimeDir string) ([]string, error) {
	dir, err := g.tempdir()
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "open-url.sock")
	p, err := g.guard("open-url-guard", sock)
	if err != nil {
		return nil, err
	}
	if err := g.waitFor(sock, p, "open-url-guard"); err != nil {
		return nil, err
	}
	// BROWSER because Python's webbrowser doesn't try xdg-open without a
	// display variable, and npm's open honors it when it can't detect a
	// desktop.
	return []string{
		"--bind", sock, runtimeDir + "/open-url.sock",
		"--setenv", "BROWSER", "/usr/bin/xdg-open",
	}, nil
}

// exchangeArgs: a drop box for output of commands the user runs on the
// host, read back instead of pasted. Bound at its host path so a command
// naming $SANDBOX_EXCHANGE's value runs verbatim on either side.
//
// Read-only: only the host writes here, and a symlink a sandbox planted
// would point that write at any host file. Links left from when it was
// read-write are dropped.
func exchangeArgs(volumeDir string) ([]string, error) {
	exchange := filepath.Join(volumeDir, "exchange")
	if err := os.MkdirAll(exchange, 0o777); err != nil {
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
	return []string{"--ro-bind", exchange, exchange, "--setenv", "SANDBOX_EXCHANGE", exchange}, nil
}

// The guards find the launcher's popup socket here.
var popupEnv = popup.Env
