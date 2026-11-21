package peer

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// The peer is this process.
	p := Describe(server)
	wd, _ := os.Getwd()
	if p.Cwd != wd {
		t.Errorf("cwd %q, want %q", p.Cwd, wd)
	}
	if len(p.Args) == 0 || p.Args[0] != os.Args[0] {
		t.Errorf("args %q", p.Args)
	}
	if !strings.HasPrefix(p.Cmdline, os.Args[0]) {
		t.Errorf("cmdline %q", p.Cmdline)
	}
}

func TestDescribeUnknown(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if p := Describe(a); p.Cwd != "unknown" || p.Cmdline != "unknown" || p.Args != nil || p.Session != 0 {
		t.Errorf("Describe = %+v", p)
	}
}

func TestCmdline(t *testing.T) {
	args := [][]byte{[]byte("/bin/sh"), []byte("-c"), []byte("echo hi"), []byte(""), []byte("marker\x1b[2J"), {0xff}}
	want := `/bin/sh -c "echo hi" "" "marker\x1b[2J" ` + "�"
	if got := Cmdline(args); got != want {
		t.Errorf("Cmdline = %s\nwant      %s", got, want)
	}
}

func TestSession(t *testing.T) {
	for stat, want := range map[string]int{
		// On a terminal, in session 4242; the name may hold anything.
		"77 (a) b) c) S 1 77 4242 34818 77 4194304 0": 4242,
		// Without a controlling terminal.
		"77 (code) S 1 77 77 0 -1 4194304 0": 0,
		"77 (x) S 1 77 0 34818 -1":           0,
		"77 (x) S 1":                         0,
		"":                                   0,
	} {
		if got := session(stat); got != want {
			t.Errorf("session(%q) = %d, want %d", stat, got, want)
		}
	}
}
