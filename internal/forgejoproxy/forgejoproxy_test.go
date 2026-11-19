package forgejoproxy

import (
	"encoding/json/v2"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mgnsk/sandbox/internal/apiproxy/apiproxytest"
	"github.com/mgnsk/sandbox/internal/popup"
)

const host = "forgejo.example"

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func keys(hosts map[string]any) map[string]any {
	return map[string]any{"hosts": hosts, "aliases": map[string]any{}, "default_ssh": []any{}}
}

func app(token string) map[string]string {
	return map[string]string{"type": "Application", "token": token}
}

func TestHostTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	writeJSON(t, path, keys(map[string]any{
		"a.example": app("app-token"),
		"B.example:3000/forgejo": map[string]any{
			"type": "OAuth", "token": "oauth-token", "refresh_token": "r", "expires_at": "2030-01-01T00:00:00Z",
		},
		"c.example": 1,
		"d.example": app("bad token"),
	}))
	want := map[string]string{"a.example": "app-token", "b.example:3000": "oauth-token"}
	if got := hostTokens(path); !maps.Equal(got, want) {
		t.Errorf("hostTokens = %v", got)
	}
	for _, content := range []string{"", "not json", "[]", `{"hosts": []}`} {
		os.WriteFile(path, []byte(content), 0o600)
		if got := hostTokens(path); len(got) != 0 {
			t.Errorf("%q: %v", content, got)
		}
	}
}

func TestKeysPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/data")
	if got := KeysPath(); got != "/data/forgejo-cli/keys.json" {
		t.Errorf("KeysPath = %q", got)
	}
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/home/u")
	if got := KeysPath(); got != "/home/u/.local/share/forgejo-cli/keys.json" {
		t.Errorf("KeysPath = %q", got)
	}
}

type world struct {
	upstream         *apiproxytest.Upstream
	popups           *apiproxytest.Popups
	keys, tokensFile string
	client           *http.Client
}

func newWorld(t *testing.T) *world {
	dir := t.TempDir()
	w := &world{
		upstream:   apiproxytest.NewUpstream(t),
		popups:     &apiproxytest.Popups{},
		keys:       filepath.Join(dir, "keys.json"),
		tokensFile: filepath.Join(dir, "forgejo-tokens.json"),
	}
	p := New(w.tokensFile, w.keys)
	p.Ask = w.popups.Ask
	w.upstream.Wire(p)
	h, u := apiproxytest.ServeHTTPS(t, p)
	w.client = apiproxytest.Client(h, u)
	return w
}

func (w *world) do(t *testing.T, method, url string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(`{"title":"x"}`))
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

func (w *world) lastAuth() string {
	seen := w.upstream.Seen()
	return seen[len(seen)-1].Header.Get("Authorization")
}

// Both sources are read per request: a login on the host or a project
// token applies without a restart, the project's winning.
func TestTokensPerRequest(t *testing.T) {
	w := newWorld(t)
	status, msg := w.do(t, "GET", "https://"+host+"/api/v1/user")
	if status != 403 || !strings.Contains(msg, "sandbox --fj-token "+host) || !strings.Contains(msg, "fj --host "+host+" auth add-token") {
		t.Errorf("no token: %d %q", status, msg)
	}
	writeJSON(t, w.keys, keys(map[string]any{host: app("host-token")}))
	if status, _ := w.do(t, "GET", "https://"+host+"/x"); status != 200 || w.lastAuth() != "token host-token" {
		t.Errorf("host token: %d %q", status, w.lastAuth())
	}
	writeJSON(t, w.tokensFile, map[string]string{"Forgejo.Example": "project1"})
	if w.do(t, "GET", "https://"+host+"/x"); w.lastAuth() != "token project1" {
		t.Errorf("project token: %q", w.lastAuth())
	}
	// Another port is another instance.
	if status, msg := w.do(t, "GET", "https://"+host+":3000/x"); status != 403 || !strings.Contains(msg, host+":3000") {
		t.Errorf("other port: %d %q", status, msg)
	}
}

func TestWritesAsk(t *testing.T) {
	w := newWorld(t)
	writeJSON(t, w.keys, keys(map[string]any{host: app("real-token")}))
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if status, msg := w.do(t, method, "https://"+host+"/api/v1/repos/o/r/issues"); status != 403 || !strings.Contains(msg, "declined by user") {
			t.Errorf("%s: %d %q", method, status, msg)
		}
	}
	if len(w.upstream.Seen()) != 0 {
		t.Error("a declined write reached upstream")
	}
	if asked := w.popups.Asked(); len(asked) != 4 || asked[0] != (popup.Request{
		Name: "forgejo-api-proxy",
		Text: "Allow sandboxed Forgejo API write?\n\nPOST " + host + "/api/v1/repos/o/r/issues\n",
	}) {
		t.Errorf("asked %q", asked)
	}
}

// -- end to end, through the sandbox's fj --

func TestFj(t *testing.T) {
	if _, err := exec.LookPath("fj"); err != nil {
		t.Skip("needs fj (the sandbox's wrapper) on PATH")
	}
	run := func(t *testing.T, answer popup.Answer, args ...string) (*apiproxytest.Upstream, []popup.Request, string, error) {
		dir := t.TempDir()
		upstream := apiproxytest.NewUpstream(t)
		upstream.Handler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.MarshalWrite(w, map[string]any{"login": "someone", "id": 1})
		}
		tokensFile := filepath.Join(dir, "forgejo-tokens.json")
		writeJSON(t, tokensFile, map[string]string{host: "real-token"})
		popups := &apiproxytest.Popups{Answer: answer}
		p := New(tokensFile, filepath.Join(dir, "none.json"))
		p.Ask = popups.Ask
		upstream.Wire(p)
		h, u := apiproxytest.ServeHTTPS(t, p)
		bundle := filepath.Join(dir, "bundle.pem")
		os.WriteFile(bundle, []byte(h.Info().CA), 0o600)
		cmd := exec.Command("fj", append([]string{"--host", host, "--style", "minimal"}, args...)...)
		cmd.Dir = dir
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + dir,
			"XDG_CONFIG_HOME=" + dir + "/config",
			"XDG_DATA_HOME=" + dir + "/data",
			"XDG_CACHE_HOME=" + dir + "/cache",
			"SANDBOX_FJ_PROXY=" + u.String(),
			"SANDBOX_CA_FILE=" + bundle,
			// Decoys the wrapper has to override.
			"HTTPS_PROXY=http://127.0.0.1:1",
			"https_proxy=http://127.0.0.1:1",
			"NO_PROXY=*",
		}
		out, err := cmd.CombinedOutput()
		return upstream, popups.Asked(), string(out), err
	}

	t.Run("read gets the real token", func(t *testing.T) {
		upstream, asked, out, err := run(t, popup.No, "whoami")
		if err != nil || !strings.Contains(out, "someone") || len(asked) != 0 {
			t.Fatalf("%v %q %q", err, out, asked)
		}
		for _, s := range upstream.Seen() {
			if s.Header.Get("Authorization") != "token real-token" {
				t.Errorf("upstream got %v", s.Header)
			}
		}
	})
	t.Run("declined write fails and never reaches Forgejo", func(t *testing.T) {
		upstream, asked, out, err := run(t, popup.No, "issue", "comment", "o/r#1", "hello")
		if err == nil || !strings.Contains(out, "declined by user") {
			t.Fatalf("%v %q", err, out)
		}
		for _, s := range upstream.Seen() {
			if s.Method != "GET" && s.Method != "HEAD" {
				t.Errorf("a write reached upstream: %+v", s)
			}
		}
		if len(asked) != 1 || !strings.Contains(asked[0].Text, "POST "+host+"/api/v1/repos/o/r/issues/1/comments") {
			t.Errorf("asked %q", asked)
		}
	})
	t.Run("approved write goes through", func(t *testing.T) {
		upstream, asked, out, _ := run(t, popup.Once, "issue", "comment", "o/r#1", "hello")
		var posts []apiproxytest.Seen
		for _, s := range upstream.Seen() {
			if s.Method == "POST" {
				posts = append(posts, s)
			}
		}
		if len(posts) != 1 || !strings.Contains(string(posts[0].Body), `"hello"`) || posts[0].Header.Get("Authorization") != "token real-token" {
			t.Errorf("posts %+v (%s)", posts, out)
		}
		if len(asked) != 1 {
			t.Errorf("asked %d times", len(asked))
		}
	})
}
