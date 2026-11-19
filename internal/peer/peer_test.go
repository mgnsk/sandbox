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
	if !strings.HasPrefix(p.Cmdline, os.Args[0]) {
		t.Errorf("cmdline %q", p.Cmdline)
	}
}

func TestDescribeUnknown(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if p := Describe(a); p != (Peer{"unknown", "unknown"}) {
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
