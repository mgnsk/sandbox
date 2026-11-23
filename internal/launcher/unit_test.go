package launcher

import (
	"errors"
	"maps"
	"net/netip"
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

func TestParseAllowNet(t *testing.T) {
	lookup := func(name string) ([]netip.Addr, error) {
		switch name {
		case "nas.lan":
			return []netip.Addr{netip.MustParseAddr("192.168.1.9"), netip.MustParseAddr("::ffff:10.0.0.9"), netip.MustParseAddr("fe80::9%eth0")}, nil
		case "empty.lan":
			return nil, nil
		}
		return nil, errors.New("no such host")
	}
	for spec, want := range map[string]string{
		"192.168.1.50":    "192.168.1.50/32",
		"fd00::5":         "fd00::5/128",
		"::ffff:10.0.0.1": "10.0.0.1/32",
		"192.168.1.7/24":  "192.168.1.0/24",
		"FD00::1/8":       "fd00::/8",
		"192.168.1.*":     "192.168.1.0/24",
		"192.168.*":       "192.168.0.0/16",
		"10.*":            "10.0.0.0/8",
		"10.*.*.*":        "10.0.0.0/8",
		"tailscale":       "100.64.0.0/10 fd7a:115c:a1e0::/48",
		"ALL":             "0.0.0.0/0 ::/0",
		"NAS.lan":         "192.168.1.9/32 10.0.0.9/32 fe80::9/128",
		// With ports: those only, tcp unless it says udp.
		"192.168.100.1:8080":      "192.168.100.1/32:8080/tcp",
		"192.168.100.1:8000-8100": "192.168.100.1/32:8000-8100/tcp",
		"192.168.100.1:53/udp":    "192.168.100.1/32:53/udp",
		"192.168.1.*:22/tcp":      "192.168.1.0/24:22/tcp",
		"10.0.0.0/8:7-7":          "10.0.0.0/8:7/tcp",
		"nas.lan:445":             "192.168.1.9/32:445/tcp 10.0.0.9/32:445/tcp fe80::9/128:445/tcp",
		"tailscale:22":            "100.64.0.0/10:22/tcp fd7a:115c:a1e0::/48:22/tcp",
		"[fd00::5]:8080":          "fd00::5/128:8080/tcp",
		"[fd00::/8]:53/udp":       "fd00::/8:53/udp",
		"[fd00::5]":               "fd00::5/128",
	} {
		allow, warnings, err := parseAllowNet([]string{spec}, lookup)
		var got []string
		for _, p := range allow {
			got = append(got, p.String())
		}
		if err != nil || len(warnings) != 0 || strings.Join(got, " ") != want {
			t.Errorf("%s: %q %q %v", spec, got, warnings, err)
		}
	}
	if allow, _, err := parseAllowNet([]string{"lan"}, lookup); err != nil || len(allow) != len(allowNetKeywords["lan"]) {
		t.Errorf("%v %v", allow, err)
	}
	for _, bad := range []string{
		"", "*", "*.1", "10.*.1.*", "10.1*", "1.2.3.4.*", "256.*", "01.*", "fd00::*", "192.168.1", "192.168.1.0/33",
		"10.0.0.0/8/8", "fe80::1%eth0", "a b", "nas.lan.", "-x.lan", "http://nas.lan",
		"192.168.1.50:", "192.168.1.50:0", "192.168.1.50:http", "192.168.1.50:70000", "192.168.1.50:9-8", "192.168.1.50:22/sctp",
		":22", "192.168.1:22", "[fd00::5", "[fd00::5]8080", "[fd00::5]:", "[nas.lan]:22", "[10.0.0.1]:22", "fd00::5:x",
	} {
		if _, _, err := parseAllowNet([]string{bad}, lookup); err == nil || !strings.Contains(err.Error(), "SANDBOX_ALLOW_NET") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// A name that doesn't resolve leaves the rest standing.
	allow, warnings, err := parseAllowNet([]string{"gone.lan", "10.0.0.1", "empty.lan"}, lookup)
	if err != nil || len(allow) != 1 || len(warnings) != 2 || !strings.Contains(warnings[0], "gone.lan") || !strings.Contains(warnings[1], "empty.lan") {
		t.Errorf("%v %q %v", allow, warnings, err)
	}
	t.Setenv("SANDBOX_ALLOW_NET", "tailscale, 10.* nas.lan")
	if got := allowNetSpecs([]string{"lan"}); !slices.Equal(got, []string{"lan", "tailscale", "10.*", "nas.lan"}) {
		t.Errorf("allowNetSpecs = %q", got)
	}
}

func TestNftRules(t *testing.T) {
	addrs := func(list ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range list {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	lines := func(rules string) []string {
		var out []string
		for line := range strings.Lines(rules) {
			out = append(out, strings.TrimSpace(line))
		}
		return out
	}
	const reject = " reject with icmpx type admin-prohibited"
	const blocked4 = "ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }" + reject
	const blocked6 = "ip6 daddr { fc00::/7, fe80::/10, ff00::/8, 64:ff9b:1::/48 }" + reject
	const ndp = "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report, mld-listener-done, mld2-listener-report } accept"

	// Nothing allowed, nothing known of the host: only the public internet.
	got := lines(nftRules(nil, nil, nil, false))
	want := []string{
		"table inet sandbox {", "chain out {",
		"type filter hook output priority 0; policy accept;",
		`oifname "lo" accept`,
		ndp, blocked4, blocked6,
		"}", "}",
	}
	if !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}

	// The host's addresses are refused ahead of what's allowed, the
	// nameservers reached for DNS only, and what's allowed is one element
	// per range: inside another or twice isn't a set nft takes.
	got = lines(nftRules(
		everyPort(prefixes("192.168.1.0/24", "192.168.1.50/32", "192.168.0.0/16", "10.0.0.1/32", "10.0.0.1/32", "fd00::/8", "fd7a:115c:a1e0::/48")),
		addrs("169.254.169.254", "192.168.1.2", "100.64.0.1", "fe80::2", "2001:db8::2", "192.168.1.2"),
		addrs("192.168.1.1", "fe80::1", "9.9.9.9"),
		true))
	want = []string{
		"table inet sandbox {", "chain out {",
		"type filter hook output priority 0; policy accept;",
		`oifname "lo" accept`,
		"ip daddr 169.254.1.53 meta l4proto { tcp, udp } th dport { 53, 853 } accept",
		ndp,
		"ip daddr { 169.254.169.254, 192.168.1.2, 100.64.0.1 }" + reject,
		"ip daddr { 192.168.1.1, 9.9.9.9 } meta l4proto { tcp, udp } th dport { 53, 853 } accept",
		"ip daddr { 192.168.0.0/16, 10.0.0.1 } accept",
		blocked4,
		"ip6 daddr { fe80::2, 2001:db8::2 }" + reject,
		"ip6 daddr { fe80::1 } meta l4proto { tcp, udp } th dport { 53, 853 } accept",
		"ip6 daddr { fd00::/8 } accept",
		blocked6,
		"}", "}",
	}
	if !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}

	// all: every address isn't a set element, and the host stays refused.
	got = lines(nftRules(everyPort(allowNetKeywords["all"]), addrs("192.168.1.2"), nil, false))
	want = []string{
		"table inet sandbox {", "chain out {",
		"type filter hook output priority 0; policy accept;",
		`oifname "lo" accept`,
		ndp,
		"ip daddr { 192.168.1.2 }" + reject,
		"meta nfproto ipv4 accept",
		blocked4,
		"meta nfproto ipv6 accept",
		blocked6,
		"}", "}",
	}
	if !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
}

// Entries with ports allow those only: a rule for each set of ports, after
// the host's addresses are refused like any.
func TestNftRulesWithPorts(t *testing.T) {
	allow, _, err := parseAllowNet([]string{
		"192.168.100.1:8080", "10.0.0.5", "192.168.1.*:8080", "192.168.100.1:53/udp", "[fd00::5]:8000-8100",
		"192.168.1.7:8080", "all:22", "10.9.9.9:22",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := nftRules(allow, []netip.Addr{netip.MustParseAddr("192.168.100.2")}, nil, false)
	var got []string
	for line := range strings.Lines(rules) {
		if line = strings.TrimSpace(line); strings.HasSuffix(line, "accept") && !strings.Contains(line, "icmpv6") && !strings.Contains(line, "oifname") {
			got = append(got, line)
		}
	}
	want := []string{
		"ip daddr { 192.168.100.1, 192.168.1.0/24 } tcp dport 8080 accept",
		"ip daddr { 10.0.0.5 } accept",
		"ip daddr { 192.168.100.1 } udp dport 53 accept",
		"meta nfproto ipv4 tcp dport 22 accept",
		"ip6 daddr { fd00::5 } tcp dport 8000-8100 accept",
		"meta nfproto ipv6 tcp dport 22 accept",
	}
	if !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
	if strings.Index(rules, "192.168.100.2 } reject") > strings.Index(rules, "dport 8080") {
		t.Errorf("the host isn't refused first: %s", rules)
	}
}

func TestNameservers(t *testing.T) {
	got := nameservers("# x\nnameserver 169.254.1.53\nnameserver 192.168.1.1\nnameserver 127.0.0.1\nnameserver fe80::1%eth0\nnameserver ::1\nnameserver nope\nsearch lan\n")
	if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fe80::1")}) {
		t.Errorf("%v", got)
	}
}

// pasta closes inherited fds past stdio before running its command, so the
// seccomp filter is opened by the command itself, which first loads the
// network policy and adds the prohibit routes. Run here with stand-ins for
// ip, nft and bwrap.
func TestPastaInner(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	ip := filepath.Join(dir, "ip")
	os.WriteFile(ip, []byte("#!/bin/sh\necho \"ip $*\" >> "+log+"\n"), 0o755)
	nft := filepath.Join(dir, "nft")
	os.WriteFile(nft, []byte("#!/bin/sh\necho \"nft $*\" >> "+log+"\n[ \"$2\" != /bad ]\n"), 0o755)
	seccomp := filepath.Join(dir, "seccomp.bpf")
	os.WriteFile(seccomp, make([]byte, 8), 0o644)
	args := filepath.Join(dir, "args")
	os.WriteFile(args, []byte("--x\x00"), 0o600)
	inner := func(rules string) *exec.Cmd {
		return exec.Command(bash, "-c", pastaInner, "bash", ip, nft, rules, seccomp, args, "2", "10.0.0.1", "100.1.2.3",
			"sh", "-c", `echo "run $*" >> `+log+`; test -e /proc/self/fd/10 && [ "$(tr '\0' . <&11)" = --x. ]`, "sh", "a")
	}
	if out, err := inner("/rules").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	data, _ := os.ReadFile(log)
	if want := "nft -f /rules\nip route replace prohibit 10.0.0.1\nip route replace prohibit 100.1.2.3\nrun a\n"; string(data) != want {
		t.Errorf("%q", data)
	}

	// Without the policy nothing runs.
	os.Remove(log)
	out, err := inner("/bad").CombinedOutput()
	data, _ = os.ReadFile(log)
	if err == nil || !strings.Contains(string(out), "sandbox: nft couldn't load the network policy") || string(data) != "nft -f /bad\n" {
		t.Errorf("%v %q %q", err, out, data)
	}
}

func TestPastaArgv(t *testing.T) {
	cfg := &config{Seccomp: "/s.bpf"}
	cfg.Tools.Pasta, cfg.Tools.Bash, cfg.Tools.IP, cfg.Tools.Nft, cfg.Tools.Bwrap = "pasta", "bash", "ip", "nft", "bwrap"
	// Routes for the host's global addresses and the metadata service's;
	// its link-local ones are the ruleset's alone.
	host := []netip.Addr{metadataAddr, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("169.254.7.7")}
	argv := pastaArgv(cfg, nil, nil, host, "/rules", "/args", []string{"init", "x"}, "")
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
	if !slices.Equal(inner[3:], []string{"bash", "ip", "nft", "/rules", "/s.bpf", "/args", "2", "169.254.169.254", "10.0.0.1", "bwrap", "--seccomp", "10", "--args", "11", "init", "x"}) {
		t.Errorf("%q", inner)
	}
	argv = pastaArgv(cfg, []string{"5037", "1"}, []string{"53"}, nil, "/rules", "/args", nil, "127.0.0.53")
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
	// What a read-write bind would lay the host's sockets over.
	t.Setenv("TMPDIR", "/var/scratch")
	for cwd, want := range map[string]string{
		"/":                 "it contains",
		"/tmp":              "it contains /tmp",
		"/var":              "it contains /var/",
		"/var/scratch":      "it contains /var/scratch",
		"/run":              "it contains /run",
		"/run/user/7":       "host state in $XDG_RUNTIME_DIR",
		"/run/user/7/gnupg": "host state in $XDG_RUNTIME_DIR",
		"/nix":              "it contains /nix",
	} {
		if err := checkSystem(cwd, "/run/user/7"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", cwd, err)
		}
	}
	for _, cwd := range []string{"/tmp/p", "/var/scratch/p", "/run/media/u/disk/p", "/srv/p", "/etc/nixos"} {
		if err := checkSystem(cwd, "/run/user/7"); err != nil {
			t.Errorf("%s: %v", cwd, err)
		}
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
	// Only a directory of the user's own is a work tree: not one someone
	// else could have put a .git in, like /tmp.
	if !ownDir(repo) || os.Getuid() != 0 && ownDir("/proc") {
		t.Error("ownDir")
	}
}

// How volume dirs are named must never change: existing volumes stay in
// use.
func TestVolumeName(t *testing.T) {
	if got := volumeName("/home/u/p"); got != "_home_u_p-60ad706f" {
		t.Errorf("volumeName = %q", got)
	}
}

func TestHostName(t *testing.T) {
	for project, want := range map[string]string{
		"/home/u/tools":                      "tools",
		"/home/u/My Project_2":               "my-project-2",
		"/home/u/.dotfiles":                  "dotfiles",
		"/home/u/---":                        "sandbox",
		"/":                                  "sandbox",
		"/home/u/" + strings.Repeat("a", 70): strings.Repeat("a", 63),
	} {
		if got := hostName(project); got != want {
			t.Errorf("hostName(%q) = %q, want %q", project, got, want)
		}
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
			{Name: "dotfiles", Paths: []string{"~/dotfiles"}, Priority: 10},
			{Name: "audio", Paths: []string{"~/dotfiles/nix/audio"}, Priority: 20},
			{Name: "never"},
		},
	}
	vars := map[string]string{"HOME": dir}
	pick := func(cwd string) string { return selectProfile(cfg, cwd, vars).Name }
	if got := pick(project); got != "default" {
		t.Error(got)
	}
	if got := pick(dotfiles); got != "dotfiles" {
		t.Error(got)
	}
	// Both match: the higher priority wins.
	if got := pick(filepath.Join(dotfiles, "nix/audio/x")); got != "audio" {
		t.Error(got)
	}
	// A prefix of a path component isn't a match.
	if got := pick(filepath.Join(dotfiles, "nix/audiox")); got != "dotfiles" {
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

// The launcher reads .sandbox.yml on the host; a link would let the
// sandbox pick which host file.
func TestReadProjectFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".sandbox.yml")
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

func TestHostAccessString(t *testing.T) {
	access := hostAccess{tokenCommands: tokenCommands{GitHubTokenCommand: "one\ntwo"}, GitSigningKeyCommand: "key"}
	// A command's further lines stay under it.
	want := "  run on this host at each start, for the GitHub token:\n    one\n    two\n" +
		"  run on this host at each start, for git's signing key:\n    key"
	if got := access.String(); got != want {
		t.Errorf("%q", got)
	}
}

// Whose token command runs: the user's config's, then .sandbox.yml's, then
// the flake's - per guard, and per Forgejo host. What the user's config
// already sets is neither asked about nor run.
func TestTokenCommandsPrecedence(t *testing.T) {
	mine := tokenCommands{GitHubTokenCommand: "mine", ForgejoTokenCommands: map[string]string{"a.example": "mine-a"}}
	local := tokenCommands{ClaudeAPIKeyCommand: "local-claude", ForgejoTokenCommands: map[string]string{"b.example": "local-b"}}
	theirs := tokenCommands{GitHubTokenCommand: "theirs", ClaudeAPIKeyCommand: "theirs-claude",
		ForgejoTokenCommands: map[string]string{"a.example": "theirs-a", "b.example": "theirs-b", "c.example": "theirs-c"}}
	project := local.over(theirs)
	if project.GitHubTokenCommand != "theirs" || project.ClaudeAPIKeyCommand != "local-claude" ||
		!maps.Equal(project.ForgejoTokenCommands, map[string]string{"a.example": "theirs-a", "b.example": "local-b", "c.example": "theirs-c"}) {
		t.Errorf("the project's: %+v", project)
	}
	asked := project.without(mine)
	if asked.GitHubTokenCommand != "" || asked.ClaudeAPIKeyCommand != "local-claude" ||
		!maps.Equal(asked.ForgejoTokenCommands, map[string]string{"b.example": "local-b", "c.example": "theirs-c"}) {
		t.Errorf("left to approve: %+v", asked)
	}
	if len(theirs.ForgejoTokenCommands) != 3 || len(project.ForgejoTokenCommands) != 3 {
		t.Error("an argument changed")
	}
	got := mine.over(asked)
	if got.GitHubTokenCommand != "mine" || got.ClaudeAPIKeyCommand != "local-claude" ||
		!maps.Equal(got.ForgejoTokenCommands, map[string]string{"a.example": "mine-a", "b.example": "local-b", "c.example": "theirs-c"}) {
		t.Errorf("used: %+v", got)
	}
	if !noCommands(tokenCommands{}) || noCommands(asked) || !noCommands(theirs.without(theirs)) {
		t.Error("empty")
	}
	if _, err := forgejoHosts("x", map[string]string{"not a host": "c"}); err == nil {
		t.Error("bad host taken")
	}
	if h, _ := forgejoHosts("x", map[string]string{"https://A.example:443/": "c"}); !maps.Equal(h, map[string]string{"a.example": "c"}) {
		t.Errorf("normalized %v", h)
	}
}
