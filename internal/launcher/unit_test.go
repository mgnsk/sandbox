package launcher

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestParseHostPorts(t *testing.T) {
	tcp, udp, err := parseHostPorts([]string{"5037", "9000-9010", "8080/udp", "22/tcp", "7-7"})
	if err != nil || !slices.Equal(tcp, []string{"5037", "9000-9010", "22", "7"}) || !slices.Equal(udp, []string{"8080"}) {
		t.Errorf("%v %v %v", tcp, udp, err)
	}
	for _, bad := range []string{"0", "70000", "10-5", "abc", "22/sctp", "-1", "+5", "1-", ""} {
		if _, _, err := parseHostPorts([]string{bad}); err == nil || !strings.Contains(err.Error(), "SANDBOX_HOST_PORTS") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	t.Setenv("SANDBOX_HOST_PORTS", "8080/udp, 22/tcp 7")
	if got := hostPortSpecs([]string{"5037"}); !slices.Equal(got, []string{"5037", "8080/udp", "22/tcp", "7"}) {
		t.Errorf("hostPortSpecs = %q", got)
	}
}

func TestDNSForward(t *testing.T) {
	// systemd-resolved's stub: unreachable inside, so forwarded.
	resolver, text := dnsForward("# generated\nnameserver 127.0.0.53\nnameserver ::1\nnameserver 127.0.0.1\noptions edns0\nsearch lan\n")
	if resolver != "127.0.0.53" || text != "# generated\nnameserver 169.254.1.53\noptions edns0\nsearch lan\n" {
		t.Errorf("%q %q", resolver, text)
	}
	for _, conf := range []string{
		"nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\n",
		// glibc tries the first one first; leave a working one in front.
		"nameserver 192.168.1.1\nnameserver 127.0.0.53\n",
		// IPv6 loopback isn't forwarded.
		"nameserver ::1\n",
		"nameserver not-an-address\n",
		"",
	} {
		if resolver, text := dnsForward(conf); resolver != "" || text != "" {
			t.Errorf("%q: %q %q", conf, resolver, text)
		}
	}
}

// pasta closes inherited fds past stdio before running its command, so the
// seccomp filter is opened by the command itself, which first adds the
// prohibit routes. Run here with stand-ins for ip and bwrap.
func TestPastaInner(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	ip := filepath.Join(dir, "ip")
	os.WriteFile(ip, []byte("#!/bin/sh\necho \"ip $*\" >> "+log+"\n"), 0o755)
	seccomp := filepath.Join(dir, "seccomp.bpf")
	os.WriteFile(seccomp, make([]byte, 8), 0o644)
	cmd := exec.Command(bash, "-c", pastaInner, "bash", ip, seccomp, "2", "10.0.0.1", "100.1.2.3",
		"sh", "-c", `echo "run $*" >> `+log+`; test -e /proc/self/fd/10`, "sh", "a")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	data, _ := os.ReadFile(log)
	if want := "ip route replace prohibit 10.0.0.1\nip route replace prohibit 100.1.2.3\nrun a\n"; string(data) != want {
		t.Errorf("%q", data)
	}
}

func TestPastaArgv(t *testing.T) {
	cfg := &config{Seccomp: "/s.bpf"}
	cfg.Tools.Pasta, cfg.Tools.Bash, cfg.Tools.IP, cfg.Tools.Bwrap = "pasta", "bash", "ip", "bwrap"
	argv := pastaArgv(cfg, nil, nil, []string{"10.0.0.1"}, []string{"--x"}, "")
	opt := func(argv []string, flag string) string { return argv[slices.Index(argv, flag)+1] }
	for flag, want := range map[string]string{
		"-T": "none", "-U": "none", "--map-host-loopback": "none", "--map-guest-addr": "none", "-t": "127.0.0.1/1-65535,auto",
	} {
		if got := opt(argv, flag); got != want {
			t.Errorf("%s %s", flag, got)
		}
	}
	if slices.Contains(argv, "--dns-forward") || !slices.Contains(argv, "--host-lo-to-ns-lo") {
		t.Errorf("%q", argv)
	}
	inner := argv[slices.Index(argv, "--")+1:]
	if !slices.Equal(inner[3:], []string{"bash", "ip", "/s.bpf", "1", "10.0.0.1", "bwrap", "--seccomp", "10", "--x"}) {
		t.Errorf("%q", inner)
	}
	argv = pastaArgv(cfg, []string{"5037", "1"}, []string{"53"}, nil, nil, "127.0.0.53")
	if opt(argv, "-T") != "5037,1" || opt(argv, "-U") != "53" || opt(argv, "--dns-forward") != dnsForwardAddr || opt(argv, "--dns-host") != "127.0.0.53" {
		t.Errorf("%q", argv)
	}
}

func TestExpand(t *testing.T) {
	vars := map[string]string{"HOME": "/home/u", "USER": "u", "XDG_RUNTIME_DIR": "/run/user/1"}
	for value, want := range map[string]string{
		"/env/bin:$HOME/.nix-profile/bin": "/env/bin:/home/u/.nix-profile/bin",
		"$HOME/${USER}/$NOPE":             "/home/u/u/$NOPE",
		"~/x":                             "/home/u/x",
		"~":                               "/home/u",
		"/a/~b":                           "/a/~b",
		"$XDG_RUNTIME_DIR/e":              "/run/user/1/e",
	} {
		if got := expand(value, vars); got != want {
			t.Errorf("expand(%q) = %q", value, got)
		}
	}
}

func TestRealpath(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(dir, "real"), 0o755)
	os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link"))
	for path, want := range map[string]string{
		dir + "/link":             dir + "/real",
		dir + "/link/not/yet":     dir + "/real/not/yet",
		dir + "/real/../link/x/.": dir + "/real/x",
		"/":                       "/",
	} {
		if got := realpath(path); got != want {
			t.Errorf("realpath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestChecks(t *testing.T) {
	home := "/home/u"
	for _, cwd := range []string{"/home/u", "/home", "/"} {
		if err := checkCwd(cwd, home); err == nil || !strings.Contains(err.Error(), "it contains $HOME") {
			t.Errorf("%s: %v", cwd, err)
		}
	}
	for _, cwd := range []string{"/home/u/.config", "/home/u/.ssh/x", "/home/u/.local/share/sandbox"} {
		if err := checkCwd(cwd, home); err == nil || !strings.Contains(err.Error(), "host state under $HOME") {
			t.Errorf("%s: %v", cwd, err)
		}
	}
	for _, cwd := range []string{"/home/u/src/p", "/home/u2", "/srv/p", "/home/u/x.y"} {
		if err := checkCwd(cwd, home); err != nil {
			t.Errorf("%s: %v", cwd, err)
		}
	}
	for _, cwd := range []string{"/data/state", "/data/state/vol", "/data"} {
		if err := checkOutside(cwd, "/data/state"); err == nil {
			t.Errorf("%s overlaps", cwd)
		}
	}
	if err := checkOutside("/data/statex", "/data/state"); err != nil {
		t.Error(err)
	}
}

func TestProjectRoot(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	os.MkdirAll(filepath.Join(repo, "a/b"), 0o755)
	wt := filepath.Join(dir, "wt")
	os.MkdirAll(filepath.Join(wt, "sub"), 0o755)
	os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: elsewhere\n"), 0o644)
	plain := filepath.Join(dir, "plain")
	os.Mkdir(plain, 0o755)
	for cwd, want := range map[string]string{
		filepath.Join(repo, "a/b"): repo,
		filepath.Join(wt, "sub"):   wt, // A worktree's .git is a file.
		plain:                      plain,
	} {
		if got := projectRoot(cwd); got != want {
			t.Errorf("projectRoot(%s) = %s", cwd, got)
		}
	}
}

// How volume dirs are named must never change: existing volumes stay in
// use.
func TestVolumeName(t *testing.T) {
	if got := volumeName("/home/u/p"); got != "_home_u_p-60ad706f" {
		t.Errorf("volumeName = %q", got)
	}
}

func TestIsStorePath(t *testing.T) {
	hash := strings.Repeat("a", 32)
	for path, want := range map[string]bool{
		"/nix/store/" + hash + "-x":                    true,
		"/nix/store/" + hash + "-x/sub/file":           true,
		"/nix/store/" + hash + "-x/../../etc":          false,
		"/nix/store/" + hash + "-x/./y":                false,
		"/nix/store/" + hash + "-x/":                   false,
		"/nix/store/" + hash:                           false,
		"/nix/store/" + strings.Repeat("e", 32) + "-x": false, // Not in nix's base32.
		"/etc/passwd":                                  false,
		"/nix/store/short-x":                           false,
	} {
		if got := isStorePath(path); got != want {
			t.Errorf("isStorePath(%q) = %v", path, got)
		}
	}
	out := "noise\n/nix/store/" + hash + "-a\nmore noise\n/nix/store/" + hash + "-b\n"
	if got := lastStorePath(out); got != "/nix/store/"+hash+"-b" {
		t.Errorf("lastStorePath = %q", got)
	}
}

func TestSelectProfile(t *testing.T) {
	dir := t.TempDir()
	dotfiles := filepath.Join(dir, "dotfiles")
	os.MkdirAll(filepath.Join(dotfiles, "nix/audio/x"), 0o755)
	os.MkdirAll(filepath.Join(dotfiles, "nix/audiox"), 0o755)
	project := filepath.Join(dir, "p")
	os.Mkdir(project, 0o755)
	cfg := &config{
		Default: profile{Name: "default"},
		Profiles: []profile{
			{Name: "flake", ProjectFiles: []string{"flake.nix"}, Priority: 10},
			{Name: "audio", Paths: []string{"~/dotfiles/nix/audio"}, Priority: 20},
			{Name: "never"},
		},
	}
	vars := map[string]string{"HOME": dir}
	pick := func(cwd, project string) string { return selectProfile(cfg, cwd, project, vars).Name }
	if got := pick(project, project); got != "default" {
		t.Error(got)
	}
	os.WriteFile(filepath.Join(project, "flake.nix"), nil, 0o644)
	if got := pick(project, project); got != "flake" {
		t.Error(got)
	}
	if got := pick(filepath.Join(dotfiles, "nix/audio/x"), dotfiles); got != "audio" {
		t.Error(got)
	}
	// A prefix of a path component isn't a match.
	if got := pick(filepath.Join(dotfiles, "nix/audiox"), dotfiles); got != "default" {
		t.Error(got)
	}
	// Both match: the higher priority wins.
	os.WriteFile(filepath.Join(dotfiles, "flake.nix"), nil, 0o644)
	if got := pick(filepath.Join(dotfiles, "nix/audio/x"), dotfiles); got != "audio" {
		t.Error(got)
	}
}

func TestBindArgs(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	home := filepath.Join(dir, "home")
	project := filepath.Join(home, "p")
	other := filepath.Join(dir, "other")
	ref := filepath.Join(dir, "ref")
	os.MkdirAll(filepath.Join(other, ".git"), 0o755)
	os.MkdirAll(project, 0o755)
	os.Mkdir(ref, 0o755)
	os.Symlink(ref, filepath.Join(home, "link"))
	binds := []bind{
		{Src: ref, Mode: "ro", Optional: true},
		// Its history is none of another project's business.
		{Src: other, Mode: "ro", HideGit: true},
		// No .git there to hide.
		{Src: ref, Dst: "/ref2", Mode: "ro", HideGit: true},
		{Src: "~/x", Dst: "$HOME/y", Mode: "rw"},
		{Src: "~/z", Mode: "rw", Optional: true},
		// Resolved.
		{Src: "~/link", Mode: "ro"},
		// A repo bound for reference is read-write with .git when it is
		// the project - the bind at the end covers it.
		{Src: project, Mode: "ro", HideGit: true},
		{Src: project, Dst: "/elsewhere", Mode: "ro"},
	}
	got := bindArgs(binds, map[string]string{"HOME": home}, project)
	want := bwrapArgs{
		"--ro-bind-try", ref, ref,
		"--ro-bind", other, other,
		"--tmpfs", other + "/.git",
		"--ro-bind", ref, "/ref2",
		"--bind", home + "/x", home + "/y",
		"--bind-try", home + "/z", home + "/z",
		"--ro-bind", ref, ref,
		"--ro-bind", project, "/elsewhere",
		"--bind", project, project,
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// A host GH_TOKEN would let gh inside reach the API directly, around the
// write popups; only passEnv and the profile's own variables get in.
func TestInsideEnv(t *testing.T) {
	t.Setenv("LANG", "C.UTF-8")
	t.Setenv("GH_TOKEN", "host-token")
	cfg := &config{PassEnv: []string{"LANG", "TERM_UNSET_HERE"}}
	p := profile{Env: map[string]string{"PATH": "/env/bin:$HOME/bin", "A": "~"}}
	vars := map[string]string{"HOME": "/home/u", "USER": "u", "XDG_RUNTIME_DIR": "/run/u"}
	want := map[string]string{
		"HOME": "/home/u", "USER": "u", "LOGNAME": "u", "XDG_RUNTIME_DIR": "/run/u",
		"LANG": "C.UTF-8", "PATH": "/env/bin:/home/u/bin", "A": "/home/u",
	}
	if got := insideEnv(cfg, p, vars); !maps.Equal(got, want) {
		t.Errorf("insideEnv = %v", got)
	}
}

func TestReadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	read := func(content string) (*manifest, error) {
		os.WriteFile(path, []byte(content), 0o644)
		return readManifest(path)
	}
	m, err := read(`{"claudeDir": "/nix/store/` + strings.Repeat("a", 32) + `-c", "binds": [{"src": "~/x", "dst": null, "mode": "rw", "optional": false, "hideGit": false}], "hostPorts": ["5432"], "command": ["true"]}`)
	if err != nil || len(m.Binds) != 1 || m.Binds[0].Mode != "rw" || m.HostPorts[0] != "5432" || m.Command[0] != "true" {
		t.Errorf("%+v %v", m, err)
	}
	// It comes out of a sandbox; nothing in it is taken on trust.
	for _, bad := range []string{
		`{`,
		`{"claudeDir": "/etc/claude-code"}`,
		`{"claudeDir": "/nix/store/` + strings.Repeat("a", 32) + `-x/../../etc"}`,
		`{"env": {"A": "b"}}`,
		`{"binds": [{"src": "~/x", "mode": "rwx"}]}`,
		`{"binds": [{"src": "~/x"}]}`,
		`{"binds": [{"src": "~/x", "mode": "ro", "optional": "yes"}]}`,
		`{"binds": [{"src": "~/x", "mode": "ro", "extra": 1}]}`,
		`{"hostPorts": [5432]}`,
		`{"command": []}`,
		`{"command": "ls"}`,
		`{"command": ["a"], "command": ["b"]}`,
	} {
		if _, err := read(bad); err == nil {
			t.Errorf("%s read", bad)
		}
	}
}

// The launcher reads sandbox.nix on the host; a link would let the sandbox
// pick which host file.
func TestReadProjectFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sandbox.nix")
	os.Symlink("/etc/passwd", path)
	if _, err := readProjectFile(path); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("link: %v", err)
	}
	os.Remove(path)
	syscall.Mkfifo(path, 0o644)
	if _, err := readProjectFile(path); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("fifo: %v", err)
	}
}

func TestApplyProject(t *testing.T) {
	p := profile{ClaudeDir: "/store/claude-default", Binds: []bind{{Src: "a"}}}
	m := &manifest{ClaudeDir: "/store/claude-project", Binds: []bind{{Src: "b"}}}
	got := applyProject(p, m)
	if got.ClaudeDir != "/store/claude-project" || len(got.Binds) != 2 || len(p.Binds) != 1 {
		t.Errorf("%+v", got)
	}
	// Without Claude Code in the profile, none comes in through the
	// project.
	if got := applyProject(profile{}, m); got.ClaudeDir != "" {
		t.Errorf("%+v", got)
	}
}

func TestHostAccessString(t *testing.T) {
	access := hostAccess{
		Binds:     []bind{{Src: "~/d", Mode: "rw"}, {Src: "/srv/x", Dst: "/x", Mode: "ro", Optional: true}},
		HostPorts: []string{"5432"},
	}
	want := "  bind ~/d (read-write)\n  bind /srv/x at /x (read-only, optional)\n  host port 5432"
	if got := access.String(); got != want {
		t.Errorf("%q", got)
	}
}

func TestProjectTokenCommands(t *testing.T) {
	cfg := &config{}
	cfg.Guards.GitHub, cfg.Guards.Forgejo = true, true
	prof := profile{GitHubTokenCommand: "mine", ForgejoTokenCommands: map[string]string{"a.example": "mine-a"}}
	m := &manifest{GitHubTokenCommand: "theirs", ForgejoTokenCommands: map[string]string{"a.example": "theirs-a", "b.example": "theirs-b"}}
	projectTokenCommands(cfg, prof, m)
	if m.GitHubTokenCommand != "" || !maps.Equal(m.ForgejoTokenCommands, map[string]string{"b.example": "theirs-b"}) {
		t.Errorf("left to approve: %+v", m)
	}
	got := withProjectTokenCommands(prof, m)
	if got.GitHubTokenCommand != "mine" || !maps.Equal(got.ForgejoTokenCommands, map[string]string{"a.example": "mine-a", "b.example": "theirs-b"}) {
		t.Errorf("used: %+v", got)
	}
	// Off guards: nothing to approve or run.
	cfg.Guards.GitHub, cfg.Guards.Forgejo = false, false
	m = &manifest{GitHubTokenCommand: "x", ForgejoTokenCommands: map[string]string{"c.example": "x"}}
	projectTokenCommands(cfg, profile{}, m)
	if m.GitHubTokenCommand != "" || len(m.ForgejoTokenCommands) != 0 {
		t.Errorf("off: %+v", m)
	}
	if _, err := forgejoHosts("x", map[string]string{"not a host": "c"}); err == nil {
		t.Error("bad host taken")
	}
	if h, _ := forgejoHosts("x", map[string]string{"https://A.example:443/": "c"}); !maps.Equal(h, map[string]string{"a.example": "c"}) {
		t.Errorf("normalized %v", h)
	}
}
