// Package e2e launches real sandboxes - pasta, bwrap, every guard - and
// checks what the sandboxed process actually sees.
//
// A flag on a command line can't tell you bwrap honored it, that a nested
// namespace didn't reintroduce root, or that pasta's netns is actually
// reachable - that gap is how the sandbox once ran the sandboxed process as
// uid 0 without any test catching it. (The command line itself is the
// launcher's tests'.) They run the `sandbox` built from this flake:
// $SANDBOX_BIN, else `sandbox` on PATH, e.g.
//
//	SANDBOX_BIN=$(nix build --print-out-paths .#checks.x86_64-linux.default)/bin/sandbox go test ./e2e
//
// and need a real host: unprivileged user namespaces are unavailable inside a
// running sandbox (`--disable-userns` blocks exactly that), so they skip
// themselves there. Each gets its own $SANDBOX_STATE_DIR.
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mgnsk/sandbox/internal/secretservice/secretservicetest"
)

// sandbox is the built sandbox to run.
func sandbox(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("SANDBOX_BIN"); bin != "" {
		return bin
	}
	bin, err := exec.LookPath("sandbox")
	if err != nil {
		t.Skip("needs a built sandbox ($SANDBOX_BIN)")
	}
	return bin
}

// usernsUsable says whether bwrap can make the namespaces a sandbox needs
// here.
func usernsUsable() bool {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		bwrap = "/nix/var/nix/profiles/default/bin/bwrap"
	}
	err = exec.Command(bwrap, "--unshare-all", "--unshare-user", "--disable-userns", "--ro-bind", "/", "/", "true").Run()
	var exit *exec.ExitError
	// No bwrap to probe with: let the sandbox itself fail loudly.
	return err == nil || !errors.As(err, &exit)
}

// project is a throwaway git repo with a state dir next to it, and a host
// session bus of its own with a keyring on it, for the Secret Service
// guard: never the user's.
type project struct {
	bin, dir, state string
	hostBus         string
}

func newProject(t *testing.T) project {
	t.Helper()
	bin := sandbox(t)
	if !usernsUsable() {
		t.Skip("needs a real host: unprivileged user namespaces are unavailable here (e.g. inside a sandbox)")
	}
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	p := project{bin: bin, dir: filepath.Join(tmp, "project"), state: filepath.Join(tmp, "state")}
	os.MkdirAll(filepath.Join(p.dir, ".git"), 0o755)
	os.Mkdir(p.state, 0o755)
	p.hostBus = secretservicetest.Bus(t)
	secretservicetest.Serve(t, p.hostBus, false)
	return p
}

// testTools is a PATH line for the scripts run inside: the directories of
// the tools they use beyond the sandbox's own userland, from the test's
// PATH (the dev shell), by store path - /nix/store is visible inside, and
// the sandbox brings none of them itself.
func testTools(t *testing.T) string {
	t.Helper()
	var dirs []string
	for _, tool := range []string{"python3", "curl", "ip", "getent"} {
		path, err := exec.LookPath(tool)
		if err == nil {
			path, err = filepath.EvalSymlinks(path)
		}
		if err != nil || !strings.HasPrefix(path, "/nix/store/") {
			t.Skipf("needs %s from the store on PATH (the dev shell has it)", tool)
		}
		dirs = append(dirs, filepath.Dir(path))
	}
	return "PATH=" + strings.Join(dirs, ":") + ":$PATH\n"
}

func (p project) command(cwd string, env map[string]string, args ...string) *exec.Cmd {
	cmd := exec.Command(p.bin, args...)
	cmd.Dir = cwd
	if cwd == "" {
		cmd.Dir = p.dir
	}
	cmd.Env = append(os.Environ(), "SANDBOX_STATE_DIR="+p.state, "DBUS_SESSION_BUS_ADDRESS="+p.hostBus)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd
}

type result struct {
	code           int
	stdout, stderr string
}

// run feeds script to the sandboxed bash's stdin: with no command the
// sandbox runs `bash --login`, which, with stdin not a terminal, runs it
// non-interactively and exits at EOF.
func (p project) run(t *testing.T, script string, env map[string]string, args ...string) result {
	t.Helper()
	return p.runIn(t, "", script, env, args...)
}

func (p project) runIn(t *testing.T, cwd, script string, env map[string]string, args ...string) result {
	t.Helper()
	cmd := p.command(cwd, env, args...)
	cmd.Stdin = strings.NewReader(testTools(t) + script)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	cmd.WaitDelay = 10 * time.Minute
	err := cmd.Run()
	r := result{stdout: out.String(), stderr: errOut.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return r
}

func (r result) ok(t *testing.T) result {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	return r
}

func volumeName(project string) string {
	digest := sha256.Sum256([]byte(project))
	return strings.ReplaceAll(project, "/", "_") + "-" + hex.EncodeToString(digest[:4])
}

func TestRefusesHomeThroughASymlink(t *testing.T) {
	bin := sandbox(t)
	home, _ := os.UserHomeDir()
	link := filepath.Join(t.TempDir(), "home-link")
	os.Symlink(home, link)
	cmd := exec.Command("bash", "-c", `cd "$1" && exec "$2" true`, "bash", link, bin)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), "refusing") {
		t.Errorf("%v %s", err, out)
	}
}

// pasta's own user namespace maps the invoking user to uid 0 in it -
// without bwrap's --uid/--gid pinning it back, the sandboxed process looks
// like real root.
func TestNotRoot(t *testing.T) {
	r := newProject(t).run(t, "id -u; id -g\n", nil).ok(t)
	if got := strings.Fields(r.stdout); !slices.Equal(got, []string{strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())}) {
		t.Errorf("%q", got)
	}
}

func TestArgsAreTheCommand(t *testing.T) {
	if r := newProject(t).run(t, "", nil, "echo", "hello there").ok(t); strings.TrimSpace(r.stdout) != "hello there" {
		t.Errorf("%q", r.stdout)
	}
}

// Started in a subdirectory, the repo root and .git are there, read-write.
func TestASubdirectoryGetsTheWholeWorkTree(t *testing.T) {
	p := newProject(t)
	sub := filepath.Join(p.dir, "sub")
	os.Mkdir(sub, 0o755)
	if r := p.runIn(t, sub, "test -d ../.git && touch ../top && echo ok\n", nil).ok(t); strings.TrimSpace(r.stdout) != "ok" {
		t.Errorf("%q", r.stdout)
	}
	if _, err := os.Stat(filepath.Join(p.dir, "top")); err != nil {
		t.Error(err)
	}
}

// Evaluated in a nested sandbox, its default command applies.
func TestProjectSandboxNixIsApplied(t *testing.T) {
	p := newProject(t)
	os.WriteFile(filepath.Join(p.dir, "sandbox.nix"), []byte(`{ ... }: { command = [ "sh" "-c" "echo from-project" ]; }`+"\n"), 0o644)
	r := p.run(t, "", nil).ok(t)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); lines[len(lines)-1] != "from-project" {
		t.Errorf("%q", r.stdout)
	}
}

func TestTheEnvironmentIsClearedAndAllowListed(t *testing.T) {
	r := newProject(t).run(t, `echo "GH_TOKEN=[$GH_TOKEN]"; echo "SOME_HOST_VAR=[$SOME_HOST_VAR]"
echo "HOME=[$HOME]"; echo "TERM=[$TERM]"
`, map[string]string{"GH_TOKEN": "leaked-token", "SOME_HOST_VAR": "should-not-cross", "TERM": "xterm-256color"}).ok(t)
	home := os.Getenv("HOME")
	for _, want := range []string{"SOME_HOST_VAR=[]", "HOME=[" + home + "]", "TERM=[xterm-256color]"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("%q not in %q", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "leaked-token") {
		t.Error("a host GH_TOKEN reached the sandbox")
	}
}

// /usr/bin, /bin and the dynamic loader are the store's, not the host's.
func TestNoHostUserland(t *testing.T) {
	r := newProject(t).run(t, "readlink -f /usr/bin/env /bin/sh; ls /usr/bin; ls /lib 2>&1 | head -1\ncommand -v bash nix git\n", nil).ok(t)
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if !strings.HasPrefix(lines[0], "/nix/store/") || !strings.HasPrefix(lines[1], "/nix/store/") {
		t.Errorf("%q", lines[:2])
	}
	usrBin := slices.Sorted(slices.Values(lines[2:4]))
	if !slices.Equal(usrBin, []string{"env", "xdg-open"}) {
		t.Errorf("/usr/bin has %q", usrBin)
	}
	for _, path := range lines[len(lines)-3:] {
		if !strings.HasPrefix(path, "/nix/store/") {
			t.Errorf("%s not from the store", path)
		}
	}
}

// The managed /etc/bashrc loads bash-completion in every interactive shell -
// one with --rcfile like nix develop's, and a login one through
// /etc/profile - which finds a tool's completion through PATH (here git's,
// from the base set; a dev shell's through the XDG_DATA_DIRS nix develop
// sets). The files are read-only.
func TestBashCompletion(t *testing.T) {
	p := newProject(t)
	for _, shell := range []string{"bash -i", "bash --rcfile /dev/null -i", "bash -l -i"} {
		r := p.run(t, shell+" -c '_comp_load git; complete -p git' 2>/dev/null\n", nil).ok(t)
		if !strings.Contains(r.stdout, "-F __git_wrap__git_main git") {
			t.Errorf("%s: %q", shell, r.stdout)
		}
	}
	if r := p.run(t, "echo x >> /etc/bashrc\n", nil); r.code == 0 {
		t.Error("/etc/bashrc writable")
	}
}

func TestStoreAndClaudeConfigAreReadOnly(t *testing.T) {
	p := newProject(t)
	if r := p.run(t, `echo x > "$(command -v git)"`+"\n", nil); r.code == 0 || !strings.Contains(r.stderr, "Read-only file system") {
		t.Errorf("%d %q", r.code, r.stderr)
	}
	r := p.run(t, "cat /etc/claude-code/managed-settings.json; echo x > /etc/claude-code/CLAUDE.md\n", nil)
	var settings struct {
		Env map[string]any `json:"env"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &settings); err != nil || fmt.Sprint(settings.Env["DISABLE_AUTOUPDATER"]) != "1" {
		t.Errorf("%v %q", err, r.stdout)
	}
	if !strings.Contains(r.stderr, "Read-only file system") {
		t.Errorf("%q", r.stderr)
	}
}

func TestTheVolumeIsPerProject(t *testing.T) {
	p := newProject(t)
	p.run(t, `echo kept > "$HOME/kept"`+"\n", nil).ok(t)
	home, _ := os.UserHomeDir()
	if data, err := os.ReadFile(filepath.Join(p.state, volumeName(p.dir), home, "kept")); err != nil || string(data) != "kept\n" {
		t.Errorf("%v %q", err, data)
	}
	if data, err := os.ReadFile(filepath.Join(home, "kept")); err == nil && string(data) == "kept\n" {
		t.Error("written to the host home")
	}
}

func TestTheExchangeDirIsReadOnly(t *testing.T) {
	if r := newProject(t).run(t, `ln -s "$HOME/.bashrc" "$SANDBOX_EXCHANGE/foo.txt"`+"\n", nil); r.code == 0 || !strings.Contains(r.stderr, "Read-only file system") {
		t.Errorf("%d %q", r.code, r.stderr)
	}
}

// Without a token command no API guard runs, so nothing is proxied (the
// launcher's and router's own tests cover the guarded path); xdg-open
// talks to its guard.
func TestNoAPIGuardWithoutATokenAndXdgOpenTalksToItsGuard(t *testing.T) {
	r := newProject(t).run(t, `[ -z "$SANDBOX_GH_PROXY$HTTPS_PROXY$SANDBOX_CA_FILE" ] && echo env
[ -S "$XDG_RUNTIME_DIR/open-url.sock" ] && echo url-socket
echo "browser=[$BROWSER]"
xdg-open file:///etc/passwd; echo rc=$?
`, nil).ok(t)
	for _, want := range []string{"env", "url-socket", "browser=[/usr/bin/xdg-open]", "rc=4"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("%q not in %q", want, r.stdout)
		}
	}
}

// All of $HOME/go is a single per-project volume, so neither $HOME/go/pkg
// (module cache) nor $HOME/go/bin is the real host directory. go/bin sits on
// the host's PATH; go/pkg is trusted by the host's `go` toolchain, which
// extracts a module once and never re-verifies the extracted source per
// build - so sandboxed code that could rewrite a cached dependency there
// would be executed by the next `go build` on the host or in another
// project. For both: a file the sandbox writes must never reach the real
// one, and a file the host already has there must not be visible inside.
func TestGoIsAPerProjectVolume(t *testing.T) {
	p := newProject(t)
	home, _ := os.UserHomeDir()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	var script strings.Builder
	for _, sub := range []string{"pkg", "bin"} {
		dir := filepath.Join(home, "go", sub)
		os.MkdirAll(dir, 0o755)
		host := filepath.Join(dir, "test-host-"+stamp)
		os.WriteFile(host, []byte("from host\n"), 0o644)
		t.Cleanup(func() { os.Remove(host) })
		t.Cleanup(func() { os.Remove(filepath.Join(dir, "test-from-sandbox-"+stamp)) })
		fmt.Fprintf(&script, `test -e "$HOME/go/%[1]s/test-host-%[2]s" && echo %[1]s-LEAKED
mkdir -p "$HOME/go/%[1]s" && echo from sandbox > "$HOME/go/%[1]s/test-from-sandbox-%[2]s"
`, sub, stamp)
	}
	r := p.run(t, script.String(), nil).ok(t)
	if strings.Contains(r.stdout, "LEAKED") {
		t.Errorf("a host file in ~/go is visible inside: %q", r.stdout)
	}
	for _, sub := range []string{"pkg", "bin"} {
		if _, err := os.Stat(filepath.Join(home, "go", sub, "test-from-sandbox-"+stamp)); err == nil {
			t.Errorf("a file the sandbox wrote to ~/go/%s reached the host", sub)
		}
	}
}

// -- networking --

func TestTheNetworkIsReachableThroughPasta(t *testing.T) {
	if r := newProject(t).run(t, "getent hosts github.com\n", nil).ok(t); strings.TrimSpace(r.stdout) == "" {
		t.Error("no DNS")
	}
}

// freePort is a free port where real dev servers sit (3000, 5173, 8000,
// ...), below the kernel's ephemeral range.
func freePort(t *testing.T, addr string) int {
	t.Helper()
	data, _ := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	low, _ := strconv.Atoi(strings.Fields(string(data) + " 32768")[0])
	for port := 18000; port < min(low, 19000); port++ {
		if ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port))); err == nil {
			ln.Close()
			return port
		}
	}
	t.Skip("no free non-ephemeral port on", addr)
	return 0
}

// ephemeralPort is where an OAuth login's callback listener sits, from
// bind(0). A bare `-t auto` skips this range.
func ephemeralPort(t *testing.T, addr string) int {
	ln, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// httpGet is the first bytes of a reply to GET /.
func httpGet(addr string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	return string(buf[:n]), err
}

// background starts a sandbox running script and holding open until the
// test ends.
func (p project) background(t *testing.T, script string, env map[string]string) *exec.Cmd {
	t.Helper()
	cmd := p.command("", env)
	stdin, _ := cmd.StdinPipe()
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// `read` holds the sandbox open until stdin closes, so it exits
	// normally and cleans up.
	io.WriteString(stdin, testTools(t)+script+"\nread -r _\n")
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		if t.Failed() {
			t.Logf("sandbox stderr:\n%s", errOut.String())
		}
	})
	return cmd
}

// A server bound to 127.0.0.1 inside the sandbox (vite, an OAuth login's
// callback listener) must answer a host browser opening
// http://localhost:port: pasta delivers the connection to the netns's
// loopback with --host-lo-to-ns-lo. And ::1 must be refused, since a browser
// tries it first and only falls back to 127.0.0.1 when refused.
func TestALoopbackServerInsideIsReachableFromTheHost(t *testing.T) {
	for name, port := range map[string]func(*testing.T, string) int{"dev server port": freePort, "ephemeral port": ephemeralPort} {
		t.Run(name, func(t *testing.T) {
			p := newProject(t)
			port := port(t, "127.0.0.1")
			p.background(t, fmt.Sprintf("python3 -m http.server %d --bind 127.0.0.1 >/dev/null &", port), nil)
			// pasta rescans the netns for new listeners once a second.
			var reply string
			var err error
			for deadline := time.Now().Add(30 * time.Second); !strings.HasPrefix(reply, "HTTP/") && time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
				reply, err = httpGet("127.0.0.1", port)
			}
			if !strings.HasPrefix(reply, "HTTP/") {
				t.Fatalf("never answered on the host: %q %v", reply, err)
			}
			if reply, err := httpGet("::1", port); err != nil && !errors.Is(err, syscall.ECONNREFUSED) || err == nil && !strings.HasPrefix(reply, "HTTP/") {
				t.Errorf("[::1]:%d gave %q, %v - pasta's -t needs the 127.0.0.1/ host address", port, reply, err)
			}
		})
	}
}

const hostReply = "host-service"

// hostServer answers every connection on addr:port with hostReply.
func hostServer(t *testing.T, addr string) int {
	t.Helper()
	port := freePort(t, addr)
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(conn, hostReply)
			conn.Close()
		}
	}()
	return port
}

// probe connects to each addr:port from inside the sandbox; what came back
// for each addr: the reply, or the error's name.
func (p project) probe(t *testing.T, env map[string]string, targets ...string) map[string]string {
	t.Helper()
	code := `import socket, sys
for target in sys.argv[1:]:
    addr, port = target.rsplit(':', 1)
    try:
        with socket.create_connection((addr, int(port)), timeout=3) as c:
            got = c.recv(64).decode(errors='replace') or 'empty'
    except OSError as e:
        got = type(e).__name__
    print(addr, got)
`
	script := fmt.Sprintf("python3 -c \"$(cat <<'EOF'\n%sEOF\n)\" %s\n", code, strings.Join(targets, " "))
	r := p.run(t, script, env).ok(t)
	got := map[string]string{}
	for line := range strings.Lines(r.stdout) {
		if addr, reply, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			got[addr] = reply
		}
	}
	return got
}

func target(addr string, port int) string { return addr + ":" + strconv.Itoa(port) }

// pasta's default -T auto mirrored every host loopback listener into the
// netns - a host adb server on 127.0.0.1:5037 was usable from inside.
func TestHostLoopbackPorts(t *testing.T) {
	p := newProject(t)
	port := hostServer(t, "127.0.0.1")
	if got := p.probe(t, map[string]string{"SANDBOX_HOST_PORTS": ""}, target("127.0.0.1", port)); got["127.0.0.1"] == hostReply {
		t.Error("a host loopback port reachable without SANDBOX_HOST_PORTS")
	}
	if got := p.probe(t, map[string]string{"SANDBOX_HOST_PORTS": fmt.Sprintf("1, %d/tcp", port)}, target("127.0.0.1", port)); got["127.0.0.1"] != hostReply {
		t.Errorf("listed port not forwarded: %v", got)
	}
}

// pasta's default --map-host-loopback translated the gateway address to
// the host's loopback, any port.
func TestHostLoopbackIsNotReachableViaTheGateway(t *testing.T) {
	p := newProject(t)
	gw := strings.TrimSpace(p.run(t, "ip -4 route show default | awk '{print $3; exit}'\n", nil).ok(t).stdout)
	if gw == "" {
		t.Skip("no IPv4 default route in the sandbox")
	}
	port := hostServer(t, "127.0.0.1")
	if got := p.probe(t, map[string]string{"SANDBOX_HOST_PORTS": ""}, target(gw, port)); got[gw] == hostReply {
		t.Errorf("host loopback reachable via gateway %s", gw)
	}
}

// A host service on all interfaces must not be reachable through any of
// the host's own addresses (tailscale, docker bridges, ...).
func TestHostAddressesAreNotReachable(t *testing.T) {
	p := newProject(t)
	addrs, _ := net.InterfaceAddrs()
	var targets []string
	port := hostServer(t, "0.0.0.0")
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() && ipnet.IP.To4() != nil {
			targets = append(targets, target(ipnet.IP.String(), port))
		}
	}
	if len(targets) == 0 {
		t.Skip("no global IPv4 address on this host")
	}
	got := p.probe(t, map[string]string{"SANDBOX_HOST_PORTS": ""}, targets...)
	for addr, reply := range got {
		if reply == hostReply {
			t.Errorf("host service reachable via host address %s: %v", addr, got)
		}
	}
}

// Services from `devenv up` in one sandbox aren't on another sandbox's
// 127.0.0.1 (each has its own netns), but the second reaches them through
// the host when given the port in SANDBOX_HOST_PORTS.
func TestAServiceInOneSandboxIsReachableFromAnotherThroughTheHost(t *testing.T) {
	p := newProject(t)
	port := freePort(t, "127.0.0.1")
	p.background(t, fmt.Sprintf(`python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', %d))
s.listen()
while True:
    c, _ = s.accept()
    c.sendall(b'sandbox-service')
    c.close()
" &`, port), nil)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		if reply, _ := httpGet("127.0.0.1", port); reply == "sandbox-service" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the service in the sandbox never answered on the host")
		}
	}
	if got := p.probe(t, map[string]string{"SANDBOX_HOST_PORTS": ""}, target("127.0.0.1", port)); got["127.0.0.1"] == "sandbox-service" {
		t.Error("reached without SANDBOX_HOST_PORTS")
	}
	if got := p.probe(t, map[string]string{"SANDBOX_HOST_PORTS": strconv.Itoa(port)}, target("127.0.0.1", port)); got["127.0.0.1"] != "sandbox-service" {
		t.Errorf("not reached through the host: %v", got)
	}
}

// pasta holds a listed port inside to forward it to the host, so a service
// in the same sandbox gets "address in use" - what the README warns of.
func TestAListedHostPortCannotBeBoundInside(t *testing.T) {
	p := newProject(t)
	port := freePort(t, "127.0.0.1")
	r := p.run(t, fmt.Sprintf(`python3 - <<'EOF'
import errno, socket
s = socket.socket()
try:
    s.bind(('127.0.0.1', %d))
    print('BOUND')
except OSError as e:
    print('FAILED', e.errno == errno.EADDRINUSE)
EOF
`, port), map[string]string{"SANDBOX_HOST_PORTS": strconv.Itoa(port)}).ok(t)
	if strings.TrimSpace(r.stdout) != "FAILED True" {
		t.Errorf("%q", r.stdout)
	}
}

func TestBadHostPortsStopTheSandbox(t *testing.T) {
	p := newProject(t)
	for _, bad := range []string{"0", "70000", "10-5", "abc", "22/sctp"} {
		r := p.run(t, "echo started\n", map[string]string{"SANDBOX_HOST_PORTS": bad})
		if r.code == 0 || strings.Contains(r.stdout, "started") || !strings.Contains(r.stderr, "SANDBOX_HOST_PORTS") {
			t.Errorf("%s: %d %q %q", bad, r.code, r.stdout, r.stderr)
		}
	}
}

// Sharing the host's netns would expose its abstract unix sockets, like
// X11's @/tmp/.X11-unix/X<n>, which Xwayland accepts unauthenticated local
// connections on. One bound here, standing in for X11's, must be out of
// reach inside.
func TestHostAbstractSocketsAreNotReachable(t *testing.T) {
	p := newProject(t)
	name := fmt.Sprintf("/tmp/.X11-unix/sandbox-test-%d", os.Getpid())
	ln, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Reachable outside, so the check inside means something.
	if conn, err := net.Dial("unix", "@"+name); err != nil {
		t.Fatal(err)
	} else {
		conn.Close()
	}
	r := p.run(t, fmt.Sprintf(`python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect('\0%s')
    print('CONNECTED')
except OSError as e:
    print('REFUSED', e)
EOF
`, name), nil).ok(t)
	if strings.Contains(r.stdout, "CONNECTED") {
		t.Error("the sandbox reaches the host's abstract sockets")
	}
}

// -- seccomp --

const seccompProbe = `python3 - <<'EOF'
import ctypes, errno, os, socket, termios

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

def outcome(fn):
    try:
        fn()
        return "ok"
    except OSError as e:
        return errno.errorcode[e.errno]

def raw(nr, *args):
    if libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(a) for a in args]) == -1:
        return errno.errorcode[ctypes.get_errno()]
    return "ok"

def tiocsti():
    _, pty = os.openpty()
    if libc.ioctl(pty, termios.TIOCSTI, ctypes.c_char_p(b"x")) == -1:
        return errno.errorcode[ctypes.get_errno()]
    return "ok"

print([l.split()[1] for l in open("/proc/self/status") if l.startswith("Seccomp:")][0])
print(outcome(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()))
print(outcome(lambda: socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET).close()))
print(raw(425, 1, 0))  # io_uring_setup
print(raw(250, 0, 0))  # keyctl
print(tiocsti())
EOF
`

// Each rule class in internal/seccomp, as the sandboxed process sees it -
// proves bwrap actually received the fd through pasta, not just that
// --seccomp is on the command line. TIOCSTI is EIO without the filter under
// dev.tty.legacy_tiocsti=0, so EPERM shows the filter itself stops it.
func TestTheSeccompFilterIsApplied(t *testing.T) {
	r := newProject(t).run(t, seccompProbe, nil).ok(t)
	got := strings.Fields(r.stdout)
	want := []string{"2", "ok", "EAFNOSUPPORT", "ENOSYS", "EPERM", "EPERM"}
	if !slices.Equal(got, want) {
		t.Errorf("mode, inet, alg, io_uring, keyctl, tiocsti = %q, want %q", got, want)
	}
}

// -- cleanup --

var guardNames = []string{"ssh-agent-guard", "gh-api-proxy", "forgejo-api-proxy", "claude-api-proxy", "secret-service-guard", "open-url-guard", "dbus-daemon"}

// guardPids are the running guards', by their sandbox-bin subcommand or,
// for the bus, argv[0].
func guardPids() map[string]bool {
	pids := map[string]bool{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		argv := strings.Split(string(cmdline), "\x00")
		name := filepath.Base(argv[0])
		if name == "sandbox-bin" && len(argv) > 1 {
			name = argv[1]
		}
		if slices.Contains(guardNames, name) {
			pids[e.Name()] = true
		}
	}
	return pids
}

func TestGuardsDoNotSurviveTheSandbox(t *testing.T) {
	p := newProject(t)
	before := guardPids()
	p.run(t, "true\n", nil).ok(t)
	var leaked []string
	for range 50 {
		leaked = slices.Collect(func(yield func(string) bool) {
			for pid := range maps.Keys(guardPids()) {
				if !before[pid] && !yield(pid) {
					return
				}
			}
		})
		if len(leaked) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("guards survived the sandbox: %v", leaked)
}
