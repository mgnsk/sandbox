package claudeproxy

import (
	"context"
	"encoding/json/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mgnsk/sandbox/internal/apiproxy/apiproxytest"
)

const key = "sk-ant-api03-kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"

func TestAllowPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/v1/messages":                   true,
		"/v1/messages/count_tokens":      true,
		"/v1/models":                     true,
		"/v1/models/claude-opus-5-5":     true,
		"/api/claude_code/policy_limits": true,
		"/v1/messages/batches":           false,
		"/v1/files":                      false,
		"/v1/models/../files":            false,
		"/api/oauth/profile":             false,
		"/":                              false,
	} {
		if got := allowPath(path); got != want {
			t.Errorf("allowPath(%q) = %v", path, got)
		}
	}
}

type world struct {
	upstream *apiproxytest.Upstream
	popups   *apiproxytest.Popups
	keyFile  string
	client   *http.Client
}

// newWorld serves the guard on a unix socket, as Claude Code reaches it.
func newWorld(t *testing.T) *world {
	dir := t.TempDir()
	w := &world{upstream: apiproxytest.NewUpstream(t), popups: &apiproxytest.Popups{}, keyFile: filepath.Join(dir, "claude-api-key")}
	os.WriteFile(w.keyFile, []byte(key+"\n"), 0o600)
	p := New(w.keyFile)
	p.Ask = w.popups.Ask
	w.upstream.Wire(p)
	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go p.Serve(ctx, ln)
	t.Cleanup(cancel)
	w.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	return w
}

func (w *world) post(t *testing.T, url string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer sandbox-placeholder")
	req.Header.Set("X-Api-Key", "sandbox-placeholder")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	resp, err := w.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m struct {
		Message string `json:"message"`
	}
	json.UnmarshalRead(resp.Body, &m)
	return resp.StatusCode, m.Message
}

func TestMessagesGoUpstreamWithTheRealKeyOnly(t *testing.T) {
	w := newWorld(t)
	if status, msg := w.post(t, "http://api.anthropic.com/v1/messages?beta=true"); status != 200 {
		t.Fatalf("%d %q", status, msg)
	}
	// Claude Code's own requests to localhost go to the API too.
	if status, msg := w.post(t, "http://localhost/api/claude_code/policy_limits"); status != 200 {
		t.Fatalf("%d %q", status, msg)
	}
	for _, s := range w.upstream.Seen() {
		if s.Host != "api.anthropic.com" || s.Header.Get("X-Api-Key") != key || s.Header.Get("Authorization") != "" ||
			s.Header.Get("Anthropic-Version") != "2023-06-01" || string(s.Body) != "{}" {
			t.Errorf("upstream got %+v", s)
		}
	}
	if len(w.popups.Asked()) != 0 {
		t.Error("asked: a request per turn is too many for popups")
	}
}

func TestRefusals(t *testing.T) {
	w := newWorld(t)
	if status, msg := w.post(t, "http://example.com/v1/messages"); status != 403 || !strings.Contains(msg, "host not allowed") {
		t.Errorf("other host: %d %q", status, msg)
	}
	if status, msg := w.post(t, "http://api.anthropic.com/v1/files"); status != 403 || !strings.Contains(msg, "path not allowed") {
		t.Errorf("other path: %d %q", status, msg)
	}
	for _, content := range []string{"", "not a key\n"} {
		os.WriteFile(w.keyFile, []byte(content), 0o600)
		if status, msg := w.post(t, "http://api.anthropic.com/v1/messages"); status != 403 || !strings.Contains(msg, "sandbox --claude-api-key") {
			t.Errorf("key %q: %d %q", content, status, msg)
		}
	}
	os.Remove(w.keyFile)
	if status, _ := w.post(t, "http://api.anthropic.com/v1/messages"); status != 403 {
		t.Errorf("no key file: %d", status)
	}
	if n := len(w.upstream.Seen()); n != 0 {
		t.Errorf("%d requests reached upstream", n)
	}
}

func TestTheKeyIsReadPerRequest(t *testing.T) {
	w := newWorld(t)
	other := "sk-ant-api03-oooooooooooooooooooooooooooooooooooooooo"
	os.WriteFile(w.keyFile, []byte(other+"\n"), 0o600)
	w.post(t, "http://api.anthropic.com/v1/messages")
	if s := w.upstream.Seen(); len(s) != 1 || s[0].Header.Get("X-Api-Key") != other {
		t.Errorf("upstream got %+v", s)
	}
}
