package launcher

// The black-box harness: the launcher runs as a program -
// `sandbox CONFIG.json [OPTIONS] [--] [COMMAND...]`, as the nix wrapper runs
// it - and is judged by what it does from the outside: its exit status and
// output, the files it leaves, what it asks on the terminal, and the command
// line it hands to pasta.
//
// Everything the config names is a stand-in, the test binary under another
// name (see TestMain):
//
//   - pasta records its argv - with bwrap's arguments, read from its
//     --args file, in their place - and, instead of making a namespace, runs
//     the command given to the sandbox (or nothing, for a login shell) with
//     the --setenv variables and --chdir of the bwrap args. Binds whose
//     destination is under the test's $XDG_RUNTIME_DIR become symlinks
//     there, so a client inside finds a guard's socket where it would in a
//     real sandbox.
//
// The guards are the real ones.

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/mgnsk/sandbox/internal/testbin"
)

// helpers are what the test binary runs as, linked under their names in
// the harness's tools dir.
var helpers = map[string]func() int{
	"pasta": fakePasta,
	// Run inside.
	"echo-size":   echoSize,
	"agent-list":  agentList,
	"proxy-check": proxyCheck,
	"wait-ready":  waitReady,
	// On the host, for the Wayland guard, and inside.
	"wl-veil":       fakeWlVeil,
	"wayland-check": waylandCheck,
	"detached":      detached,
}

func TestMain(m *testing.M) {
	if helper, ok := helpers[filepath.Base(os.Args[0])]; ok {
		os.Exit(helper())
	}
	testbin.Main(m)
}

// logEntry is one stand-in's run.
type logEntry struct {
	Tool string   `json:"tool"`
	Argv []string `json:"argv"`
	// pasta's command line as it was, which any user of the host can read.
	Raw   []string          `json:"raw"`
	TTY   bool              `json:"tty"`
	Files map[string]string `json:"files"`
}

func writeLog(e logEntry) {
	f, err := os.OpenFile(os.Getenv("FAKE_LOG"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	json.MarshalWrite(f, e)
	io.WriteString(f, "\n")
}

const execMarker = `exec "$@"`

// expandArgs is pasta's command line with bwrap's `--args FD` replaced by
// the arguments in the file bash would open there: the fourth argument of
// the inner script.
func expandArgs(raw []string) []string {
	inner := raw[slices.Index(raw, "--")+1:]
	data, err := os.ReadFile(inner[6])
	if err != nil {
		panic(err)
	}
	at := slices.Index(raw, "--args")
	argv := slices.Clone(raw[:at])
	for arg := range strings.SplitSeq(strings.TrimSuffix(string(data), "\x00"), "\x00") {
		argv = append(argv, arg)
	}
	return append(argv, raw[at+2:]...)
}

func fakePasta() int {
	raw := os.Args[1:]
	argv := expandArgs(raw)
	bwrap := argv[slices.Index(argv, "--seccomp")+2:]
	env := map[string]string{}
	files := map[string]string{}
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	chdir := ""
loop:
	for i := 0; i < len(bwrap); i++ {
		switch a := bwrap[i]; a {
		case "--setenv":
			env[bwrap[i+1]] = bwrap[i+2]
			i += 2
		case "--bind", "--ro-bind", "--bind-try", "--ro-bind-try":
			src, dst := bwrap[i+1], bwrap[i+2]
			// Files the launcher writes for inside (resolv.conf, the CA
			// bundle) are gone with it; keep what they said.
			if fi, err := os.Stat(src); err == nil && fi.Mode().IsRegular() && fi.Size() < 1<<16 {
				data, _ := os.ReadFile(src)
				files[src] = string(data)
			}
			if strings.HasPrefix(dst, runtime+"/") {
				// Over the link an earlier run left, to a socket that's gone.
				if fi, err := os.Lstat(dst); err == nil && fi.Mode()&os.ModeSymlink != 0 {
					os.Remove(dst)
				}
				if !lexists(dst) {
					os.Symlink(src, dst)
				}
			}
			i += 2
		case "--chdir":
			chdir = bwrap[i+1]
			break loop
		}
	}
	writeLog(logEntry{Tool: "pasta", Argv: argv, Raw: raw, TTY: term.IsTerminal(0), Files: files})
	at := slices.Index(bwrap, execMarker)
	if at < 0 {
		code, _ := strconv.Atoi(os.Getenv("FAKE_PASTA_EXIT"))
		return code
	}
	command := bwrap[at+2:]
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = chdir
	// What's run inside gets the host's PATH here, not the profile's.
	cmd.Env = os.Environ()
	for k, v := range env {
		if k != "PATH" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	if err := cmd.Start(); err != nil {
		return 127
	}
	go func() {
		for sig := range signals {
			cmd.Process.Signal(sig)
		}
	}()
	cmd.Wait()
	code, _ := exitStatus(cmd, nil)
	return code
}

// echoSize says the terminal's size, and echoes a line it's typed.
func echoSize() int {
	cols, rows, _ := term.GetSize(0)
	fmt.Printf("size %d %d\nsay: ", cols, rows)
	var line string
	fmt.Scanln(&line)
	fmt.Println("got", line)
	return 0
}

// -- the harness --

// harness is a home, a project, a state dir and a config to run the
// launcher with.
type harness struct {
	t                                       *testing.T
	tmp, home, project, state, runtime      string
	tmpdir, logPath, tools, hostBin, resolv string
	cfg                                     *config
	env                                     map[string]string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	// Short: guard sockets go under it, and paths of unix sockets are
	// limited to 108 bytes.
	tmp, err := os.MkdirTemp("", "sb")
	if err != nil {
		t.Fatal(err)
	}
	tmp, _ = filepath.EvalSymlinks(tmp)
	t.Cleanup(func() { os.RemoveAll(tmp) })
	h := &harness{
		t: t, tmp: tmp,
		home:    filepath.Join(tmp, "home"),
		state:   filepath.Join(tmp, "state"),
		runtime: filepath.Join(tmp, "run"),
		tmpdir:  filepath.Join(tmp, "t"),
		logPath: filepath.Join(tmp, "log.jsonl"),
		tools:   filepath.Join(tmp, "tools"),
		hostBin: filepath.Join(tmp, "host-bin"),
		resolv:  filepath.Join(tmp, "resolv.conf"),
	}
	h.project = filepath.Join(h.home, "p")
	for _, dir := range []string{filepath.Join(h.project, ".git"), h.runtime, h.tmpdir, h.tools, h.hostBin, filepath.Join(tmp, "ssl/certs")} {
		os.MkdirAll(dir, 0o755)
	}
	os.WriteFile(filepath.Join(tmp, "ssl/certs/ca-bundle.crt"), []byte("SYSTEM CA BUNDLE\n"), 0o644)
	os.WriteFile(h.resolv, []byte("nameserver 192.0.2.53\n"), 0o644)
	seccomp := filepath.Join(tmp, "seccomp.bpf")
	os.WriteFile(seccomp, make([]byte, 8), 0o644)
	self, _ := os.Executable()
	for tool := range helpers {
		os.Symlink(self, filepath.Join(h.tools, tool))
	}
	bash, _ := exec.LookPath("bash")
	dbus, err := exec.LookPath("dbus-daemon")
	if err != nil {
		dbus = "/nonexistent/dbus-daemon"
	}

	cfg := &config{
		StateDir:   h.state,
		PassEnv:    []string{"TERM", "LANG"},
		HostEtc:    []string{"/etc/hosts"},
		Default:    h.profile("default"),
		Seccomp:    seccomp,
		ResolvConf: h.resolv,
		HostPath:   h.hostBin,
		DBusDaemon: dbus,
	}
	cfg.Guards.SSHAgent.Path = "$XDG_RUNTIME_DIR/ssh-agent.sock"
	cfg.FHS.Bin, cfg.FHS.UsrBin, cfg.FHS.NixLd, cfg.FHS.LdPath, cfg.FHS.SSL =
		"/store/fhs/bin", "/store/fhs/usr/bin", "/store/nix-ld", "/lib64/ld-linux-x86-64.so.2", filepath.Join(tmp, "ssl")
	cfg.Tools.Pasta, cfg.Tools.IP, cfg.Tools.Bash, cfg.Tools.Bwrap, cfg.Tools.Shell =
		filepath.Join(h.tools, "pasta"), "/store/ip", bash, "/store/bwrap", "/store/bash"
	h.cfg = cfg

	h.env = map[string]string{
		"HOME":            h.home,
		"USER":            "u",
		"PATH":            h.tools + ":" + os.Getenv("PATH"),
		"XDG_RUNTIME_DIR": h.runtime,
		"FAKE_LOG":        h.logPath,
		"TERM":            "xterm",
		"TMPDIR":          h.tmpdir,
		// A leak the launcher must keep out.
		"GH_TOKEN": "host-gh-token",
	}
	return h
}

func (h *harness) profile(name string) profile {
	return profile{Name: name, Env: map[string]string{"PATH": "/store/env/bin", "PROFILE": name}}
}

func (h *harness) configPath() string {
	path := filepath.Join(h.tmp, "config.json")
	data, err := json.Marshal(h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	os.WriteFile(path, data, 0o644)
	return path
}

// volume is the project's volume dir.
func (h *harness) volume() string {
	return filepath.Join(h.state, volumeName(h.project))
}

func (h *harness) environ(extra map[string]string) []string {
	var env []string
	for k, v := range h.env {
		if _, overridden := extra[k]; !overridden {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range extra {
		if v != "" || k == "SANDBOX_HOST_PORTS" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func (h *harness) command(cwd string, env map[string]string, args ...string) *exec.Cmd {
	cmd := exec.Command(testbin.Path(h.t), append([]string{"launch", "--config", h.configPath()}, args...)...)
	cmd.Dir = cwd
	if cwd == "" {
		cmd.Dir = h.project
	}
	cmd.Env = h.environ(env)
	return cmd
}

// result is how a run went.
type result struct {
	code           int
	stdout, stderr string
	log            []logEntry
}

func (h *harness) readLog() []logEntry {
	data, err := os.ReadFile(h.logPath)
	if err != nil {
		return nil
	}
	os.Remove(h.logPath)
	var log []logEntry
	for line := range bytes.Lines(data) {
		var e logEntry
		if err := json.Unmarshal(line, &e); err != nil {
			h.t.Fatal(err)
		}
		log = append(log, e)
	}
	return log
}

// run runs the launcher without a terminal, in cwd ("" for the project).
func (h *harness) run(cwd string, env map[string]string, args ...string) *result {
	h.t.Helper()
	cmd := h.command(cwd, env, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // No controlling terminal.
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	r := &result{stdout: out.String(), stderr: errOut.String(), log: h.readLog()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		h.t.Fatal(err)
	}
	return r
}

func (r *result) calls(tool string) [][]string {
	var out [][]string
	for _, e := range r.log {
		if e.Tool == tool {
			out = append(out, e.Argv)
		}
	}
	return out
}

// pasta is the outermost launcher's pasta command line: the last.
func (r *result) pasta(t *testing.T) *invocation {
	t.Helper()
	calls := r.calls("pasta")
	if len(calls) == 0 {
		t.Fatalf("pasta never ran: %s", r.stderr)
	}
	return parseInvocation(t, calls[len(calls)-1])
}

// files are the regular files bound in by the last pasta run.
func (r *result) files() map[string]string {
	var files map[string]string
	for _, e := range r.log {
		if e.Tool == "pasta" {
			files = e.Files
		}
	}
	return files
}

// refused says the launcher refused to start, with a message matching want.
func (r *result) refused(t *testing.T, want string) {
	t.Helper()
	if r.code != 1 || !strings.HasPrefix(r.stderr, "sandbox: ") || !strings.Contains(r.stderr, want) {
		t.Errorf("exit %d, stderr %q, want %q", r.code, r.stderr, want)
	}
	if len(r.calls("pasta")) != 0 {
		t.Error("started anyway")
	}
}

// invocation is a pasta command line taken apart.
type invocation struct {
	pasta, args, mountArgs, init []string
	bash, script, seccomp        string
	bwrap, chdir                 string
}

func parseInvocation(t *testing.T, argv []string) *invocation {
	t.Helper()
	sep := slices.Index(argv, "--")
	inv := &invocation{pasta: argv[:sep]}
	// bash -c SCRIPT bash IP SECCOMP ARGSFILE N ADDR... BWRAP --seccomp 10 ARGS...
	inner := argv[sep+1:]
	inv.bash, inv.script, inv.seccomp = inner[0], inner[2], inner[5]
	n, _ := strconv.Atoi(inner[7])
	inv.bwrap = inner[8+n]
	inv.args = inner[11+n:]
	chdir := slices.Index(inv.args, "--chdir")
	inv.mountArgs, inv.chdir, inv.init = inv.args[:chdir], inv.args[chdir+1], inv.args[chdir+2:]
	return inv
}

func (inv *invocation) pastaOpt(flag string) string {
	return inv.pasta[slices.Index(inv.pasta, flag)+1]
}

// tcpPorts is pasta's -T without the API guards' own ports, which every
// sandbox maps in.
func (inv *invocation) tcpPorts() string {
	env := inv.setenv()
	var ports []string
	for _, port := range strings.Split(inv.pastaOpt("-T"), ",") {
		if !strings.HasSuffix(env["SANDBOX_GH_PROXY"], ":"+port) && !strings.HasSuffix(env["SANDBOX_FJ_PROXY"], ":"+port) {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return "none"
	}
	return strings.Join(ports, ",")
}

func (inv *invocation) setenv() map[string]string {
	env := map[string]string{}
	a := inv.mountArgs
	for i := range a {
		if a[i] == "--setenv" {
			env[a[i+1]] = a[i+2]
		}
	}
	return env
}

// mounts are "flag src dst" for every bind and "flag dst" for the rest, in
// order.
func (inv *invocation) mounts() []string {
	var out []string
	a := inv.mountArgs
	for i := 0; i < len(a); i++ {
		switch a[i] {
		case "--bind", "--ro-bind", "--bind-try", "--ro-bind-try", "--symlink":
			out = append(out, strings.Join(a[i:i+3], " "))
			i += 2
		case "--tmpfs", "--dev", "--proc":
			out = append(out, strings.Join(a[i:i+2], " "))
			i++
		case "--setenv":
			i += 2
		case "--uid", "--gid", "--cap-drop":
			i++
		}
	}
	return out
}

// bind is the source bound at dst, by the last bind there.
func (inv *invocation) bind(t *testing.T, dst string) string {
	t.Helper()
	for _, m := range slices.Backward(inv.mounts()) {
		if f := strings.Fields(m); len(f) == 3 && f[2] == dst {
			return f[1]
		}
	}
	t.Fatalf("nothing bound at %s", dst)
	return ""
}

// command is the command after the login shell's exec trick; nil for a
// login shell.
func (inv *invocation) command() []string {
	at := slices.Index(inv.init, execMarker)
	if at < 0 {
		return nil
	}
	return inv.init[at+2:]
}

// -- on a terminal --

// ptyRun is the launcher on a terminal of its own, as its controlling one.
type ptyRun struct {
	h      *harness
	cmd    *exec.Cmd
	term   *os.File
	mu     sync.Mutex
	output []byte
	mark   int
	eof    chan struct{}
}

func (h *harness) pty(env map[string]string, args ...string) *ptyRun {
	h.t.Helper()
	cmd := h.command("", env, args...)
	term, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		h.t.Skip("needs a pty:", err)
	}
	p := &ptyRun{h: h, cmd: cmd, term: term, eof: make(chan struct{})}
	go func() {
		defer close(p.eof)
		buf := make([]byte, 4096)
		for {
			n, err := term.Read(buf)
			p.mu.Lock()
			p.output = append(p.output, buf[:n]...)
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	h.t.Cleanup(func() {
		cmd.Process.Kill()
		term.Close()
	})
	return p
}

func (p *ptyRun) shown() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.output)
}

// expect waits for text to show after what earlier expects saw; all shown
// up to it.
func (p *ptyRun) expect(text string) string {
	p.h.t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		p.mu.Lock()
		i := bytes.Index(p.output[p.mark:], []byte(text))
		var shown string
		if i >= 0 {
			shown = string(p.output[p.mark : p.mark+i+len(text)])
			p.mark += i + len(text)
		}
		p.mu.Unlock()
		if i >= 0 {
			return shown
		}
	}
	p.h.t.Fatalf("%q never shown; got %q", text, p.shown())
	return ""
}

func (p *ptyRun) send(text string) { io.WriteString(p.term, text) }

// wait waits for the launcher to exit; how it went.
func (p *ptyRun) wait() *result {
	p.h.t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		p.h.t.Fatalf("still running; shown %q", p.shown())
	}
	select {
	case <-p.eof:
	case <-time.After(time.Second):
	}
	r := &result{stdout: p.shown(), log: p.h.readLog()}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		r.code = exit.ExitCode()
	}
	return r
}
