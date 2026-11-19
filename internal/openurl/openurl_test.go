package openurl

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mgnsk/sandbox/internal/apiproxy/apiproxytest"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/popup"
)

func TestValidate(t *testing.T) {
	for _, url := range []string{
		"http://example.com",
		"https://example.com/a/b?c=d&e=%20f#g",
		"HTTPS://example.com",
		"HtTp://example.com",
		"http://localhost:5173/",
		"http://127.0.0.1:8080",
		"http://[::1]:8080/",
		"http://[fe80::1%25eth0]/",
	} {
		if err := Validate(url); err != nil {
			t.Errorf("%s: %v", url, err)
		}
	}
	for _, url := range []string{
		"",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"steam://run/1",
		"claude-cli://open",
		"/etc/passwd",
		"example.com",
		"--help",
		"-https://example.com",
		"https://",
		"https:///path",
		"https://exa mple.com",
		"https://exa\tmple.com",
		"https://example.com/\x1b[2J",
		"https://example.com/\x7f",
		"https://exаmple.com", // Cyrillic а.
		"https://github.com@evil.example",
		"https://user:pass@example.com",
		`https://github.com\.evil.example`,
		"https://[::1",
		"https://::1]/",
		"https://a]b[/",
		"https://a[::1]/",
		"https://[::1]x/",
		"https://[1.2.3.4]/",
		"https://[vz]/",
		"https://[nonsense]/",
		"h-t+t.p://example.com",
		"http:example.com",
	} {
		if err := Validate(url); err == nil {
			t.Errorf("%q passed", url)
		}
	}
}

type world struct {
	popups *apiproxytest.Popups
	mu     sync.Mutex
	opened []string
	fail   error
}

// guard serves a Guard on a socket; its path.
func (w *world) guard(t *testing.T) string {
	g := &Guard{Ask: w.popups.Ask, Open: func(url string) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.fail != nil {
			return w.fail
		}
		w.opened = append(w.opened, url)
		return nil
	}}
	path := filepath.Join(t.TempDir(), "open-url.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go guard.Serve(ctx, ln, g.Handle)
	t.Cleanup(cancel)
	return path
}

func (w *world) Opened() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.opened)
}

// ask sends data as a client does; the guard's reply.
func ask(t *testing.T, path, data string) string {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, data)
	conn.CloseWrite()
	reply, _ := io.ReadAll(conn)
	return string(reply)
}

func TestOpens(t *testing.T) {
	w := &world{popups: &apiproxytest.Popups{Answer: popup.Once}}
	path := w.guard(t)
	if got := ask(t, path, "https://example.com/x\n"); got != "ok\n" {
		t.Errorf("reply %q", got)
	}
	// Only the first line counts; one without a newline is read to the end.
	ask(t, path, "https://example.com\nfile:///etc/passwd\n")
	ask(t, path, "https://example.com/y")
	if got := w.Opened(); !slices.Equal(got, []string{"https://example.com/x", "https://example.com", "https://example.com/y"}) {
		t.Errorf("opened %q", got)
	}
}

func TestRefusedWithoutAsking(t *testing.T) {
	w := &world{popups: &apiproxytest.Popups{Answer: popup.Always}}
	path := w.guard(t)
	for data, want := range map[string]string{
		"file:///etc/passwd\n":                             "denied: only http and https URLs can be opened\n",
		"https://example.com/\xff\n":                       "denied: URL too long or not UTF-8\n",
		"https://example.com/" + strings.Repeat("a", 4077): "denied: URL too long or not UTF-8\n",
	} {
		if got := ask(t, path, data); got != want {
			t.Errorf("%.40q: %q", data, got)
		}
	}
	if len(w.popups.Asked()) != 0 || len(w.Opened()) != 0 {
		t.Errorf("asked %q, opened %q", w.popups.Asked(), w.Opened())
	}
}

func TestTheAnswerDecides(t *testing.T) {
	for answer, want := range map[popup.Answer]string{
		popup.Once:   "ok\n",
		popup.Always: "ok\n",
		popup.No:     "denied: not approved\n",
	} {
		w := &world{popups: &apiproxytest.Popups{Answer: answer}}
		if got := ask(t, w.guard(t), "https://example.com\n"); got != want {
			t.Errorf("%s: %q", answer, got)
		}
	}
}

func TestPopupShowsHostURLAndRequester(t *testing.T) {
	w := &world{popups: &apiproxytest.Popups{}}
	url := "https://example.com/" + strings.Repeat("a", 3000)
	ask(t, w.guard(t), url+"\n")
	asked := w.popups.Asked()
	if len(asked) != 1 || asked[0].Name != "open-url-guard" {
		t.Fatalf("asked %q", asked)
	}
	wd, _ := os.Getwd()
	text := asked[0].Text
	for _, want := range []string{
		"Open in the host's browser?\n\n",
		"  host:     example.com\n",
		"  cwd:      " + wd + "\n",
		"  command:  " + os.Args[0],
		// Whole, not truncated: a URL is approved for exactly what's on
		// screen.
		"\n" + url + "\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%.60q not in %.200q", want, text)
		}
	}
}

func TestAlwaysIsForThisGuard(t *testing.T) {
	w := &world{popups: &apiproxytest.Popups{Answer: popup.Always}}
	path := w.guard(t)
	ask(t, path, "https://example.com\n")
	w.popups.Answer = popup.No
	if got := ask(t, path, "https://other.example\n"); got != "ok\n" {
		t.Errorf("after always: %q", got)
	}
	// It doesn't cover an invalid URL.
	if got := ask(t, path, "file:///etc/passwd\n"); !strings.HasPrefix(got, "denied:") {
		t.Errorf("invalid after always: %q", got)
	}
	if got := ask(t, w.guard(t), "https://example.com\n"); got != "denied: not approved\n" {
		t.Errorf("a new guard: %q", got)
	}
	if n := len(w.popups.Asked()); n != 2 {
		t.Errorf("asked %d times", n)
	}
}

func TestFailingToOpenIsReported(t *testing.T) {
	w := &world{popups: &apiproxytest.Popups{Answer: popup.Once}, fail: errors.New("no such file")}
	if got := ask(t, w.guard(t), "https://example.com\n"); got != "denied: couldn't run xdg-open: no such file\n" {
		t.Errorf("reply %q", got)
	}
}
