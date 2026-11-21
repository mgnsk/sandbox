package popup

import (
	"encoding/json/v2"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLauncher answers every request at path with answer, recording them.
func fakeLauncher(t *testing.T, answer string) (path string, requests <-chan Request) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "popup.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reqs := make(chan Request, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req Request
			if json.UnmarshalRead(conn, &req) == nil {
				reqs <- req
			}
			_, _ = io.WriteString(conn, answer)
			conn.Close()
		}
	}()
	return path, reqs
}

func TestAskAt(t *testing.T) {
	for answer, want := range map[string]Answer{
		"once":                      Once,
		"always":                    Always,
		"no":                        No,
		"":                          No,
		"garbage":                   No,
		strings.Repeat("once", 100): No,
	} {
		path, requests := fakeLauncher(t, answer)
		if got := AskAt(path, Request{Name: "g", Text: "text"}); got != want {
			t.Errorf("answer %q: got %q, want %q", answer, got, want)
		}
		if req := <-requests; req != (Request{Name: "g", Text: "text"}) {
			t.Errorf("request %+v", req)
		}
	}
}

func TestAskWithoutALauncher(t *testing.T) {
	t.Setenv(Env, "")
	if got := Ask(Request{Name: "g", Text: "text"}); got != No {
		t.Errorf("no socket: %q", got)
	}
	t.Setenv(Env, filepath.Join(t.TempDir(), "gone.sock"))
	if got := Ask(Request{Name: "g", Text: "text"}); got != No {
		t.Errorf("socket gone: %q", got)
	}
}

func TestApprovals(t *testing.T) {
	var a Approvals
	asked := 0
	ask := func(answer Answer) func() Answer {
		return func() Answer { asked++; return answer }
	}
	for range 2 {
		if !a.Approve(ask(Once)) {
			t.Fatal("once not approved")
		}
	}
	if asked != 2 {
		t.Fatalf("once: asked %d", asked)
	}
	if a.Approve(ask(No)) {
		t.Fatal("no approved")
	}
	if !a.Approve(ask(Always)) || !a.Approve(ask(No)) || asked != 4 {
		t.Fatalf("always: asked %d", asked)
	}
}

// Requests queued behind an "always" answer see it instead of asking.
func TestApprovalsQueueBehindAlways(t *testing.T) {
	var a Approvals
	var asked atomic.Int32
	release := make(chan struct{})
	ask := func() Answer {
		asked.Add(1)
		<-release
		return Always
	}
	var wg sync.WaitGroup
	results := make(chan bool, 4)
	for range 4 {
		wg.Go(func() { results <- a.Approve(ask) })
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Error("not approved")
		}
	}
	if n := asked.Load(); n != 1 {
		t.Errorf("asked %d times", n)
	}
}

func TestClean(t *testing.T) {
	if got := Clean("a\x1b[2Jb\u202ec\nd"); got != "a?[2Jb?c?d" {
		t.Errorf("Clean = %q", got)
	}
	if got := CleanText("a\x1b\nb"); got != "a?\nb" {
		t.Errorf("CleanText = %q", got)
	}
	if got := CleanLimit("\x1b[31mred"+strings.Repeat("a", 300), 200); got != "?[31mred"+strings.Repeat("a", 192)+"…" {
		t.Errorf("CleanLimit = %q", got)
	}
}
