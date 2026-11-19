package xdgopen

import (
	"bufio"
	"io"
	"net"
	"path/filepath"
	"testing"
)

// guard answers each request at dir's open-url.sock with reply; the URLs it
// got.
func guard(t *testing.T, dir, reply string) <-chan string {
	ln, err := net.Listen("unix", filepath.Join(dir, "open-url.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	urls := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			urls <- line
			io.WriteString(conn, reply)
			conn.Close()
		}
	}()
	return urls
}

func TestMain_(t *testing.T) {
	for reply, want := range map[string]int{
		"ok\n":                   0,
		"denied: not approved\n": exitFailed,
		"":                       exitFailed, // Hung up.
	} {
		dir := t.TempDir()
		t.Setenv("XDG_RUNTIME_DIR", dir)
		urls := guard(t, dir, reply)
		if got := Main([]string{"xdg-open", "https://example.com"}); got != want {
			t.Errorf("reply %q: exit %d, want %d", reply, got, want)
		}
		if url := <-urls; url != "https://example.com\n" {
			t.Errorf("sent %q", url)
		}
	}
}

func TestWithoutAGuard(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if got := Main([]string{"xdg-open", "https://example.com"}); got != exitFailed {
		t.Errorf("exit %d", got)
	}
}

func TestUsage(t *testing.T) {
	for _, argv := range [][]string{{"xdg-open"}, {"xdg-open", "a", "b"}} {
		if got := Main(argv); got != exitSyntax {
			t.Errorf("%q: exit %d", argv, got)
		}
	}
}
