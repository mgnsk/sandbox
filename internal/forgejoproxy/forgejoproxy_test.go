package forgejoproxy

import (
	"encoding/json/v2"
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

type world struct {
	upstream *apiproxytest.Upstream
	popups   *apiproxytest.Popups
	tokens   map[string]string
	client   *http.Client
}

func newWorld(t *testing.T) *world {
	w := &world{
		upstream: apiproxytest.NewUpstream(t),
		popups:   &apiproxytest.Popups{},
		tokens:   map[string]string{},
	}
	p := New(w.tokens)
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

// notHandled says whether the guard turned down the CONNECT for url's
// host, leaving it to the router to reach directly.
func (w *world) notHandled(t *testing.T, url string) bool {
	t.Helper()
	resp, err := w.client.Get(url)
	if err == nil {
		resp.Body.Close()
		return false
	}
	return strings.Contains(err.Error(), "Not Found")
}

func (w *world) lastAuth() string {
	seen := w.upstream.Seen()
	return seen[len(seen)-1].Header.Get("Authorization")
}

// Only the tokens the launcher gives it count (looked up per request, the
// map shared with the test). A host without one isn't the guard's at all -
// even when the host's fj is logged in to it.
func TestTokensPerRequest(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	os.MkdirAll(filepath.Join(data, "forgejo-cli"), 0o755)
	writeJSON(t, filepath.Join(data, "forgejo-cli", "keys.json"), map[string]any{
		"hosts": map[string]any{host: map[string]string{"type": "Application", "token": "host-token"}},
	})
	w := newWorld(t)
	if !w.notHandled(t, "https://"+host+"/api/v1/user") {
		t.Error("no project token: handled")
	}
	w.tokens[host] = "project1"
	if w.do(t, "GET", "https://"+host+"/x"); w.lastAuth() != "token project1" {
		t.Errorf("project token: %q", w.lastAuth())
	}
	// Another port is another instance.
	if !w.notHandled(t, "https://"+host+":3000/x") {
		t.Error("other port: handled")
	}
}

func TestWritesAsk(t *testing.T) {
	w := newWorld(t)
	w.tokens[host] = "real-token"
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
		t.Errorf("asked %+v", asked)
	}
}

// fj auth login's token exchange never reaches the instance, however the
// path is spelled.
func TestOAuthRefused(t *testing.T) {
	w := newWorld(t)
	w.tokens[host] = "real-token"
	for _, p := range []string{"/login/oauth/access_token", "/login/oauth", "//login/./OAuth/access_token", "/x/../login/oauth/authorize"} {
		if status, msg := w.do(t, "POST", "https://"+host+p); status != 403 || !strings.Contains(msg, "path not allowed") {
			t.Errorf("%s: %d %q", p, status, msg)
		}
	}
	if len(w.upstream.Seen()) != 0 || len(w.popups.Asked()) != 0 {
		t.Error("an OAuth request got through")
	}
	if status, _ := w.do(t, "GET", "https://"+host+"/login/oauthx"); status != 200 {
		t.Errorf("neighbour path: %d", status)
	}
}

// -- end to end, with a real fj --

func TestFj(t *testing.T) {
	if _, err := exec.LookPath("fj"); err != nil {
		t.Skip("needs fj on PATH")
	}
	run := func(t *testing.T, answer popup.Answer, args ...string) (*apiproxytest.Upstream, []popup.Request, string, error) {
		dir := t.TempDir()
		upstream := apiproxytest.NewUpstream(t)
		upstream.Handler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.MarshalWrite(w, map[string]any{"login": "someone", "id": 1})
		}
		popups := &apiproxytest.Popups{Answer: answer}
		p := New(map[string]string{host: "real-token"})
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
			// What the sandbox's router hands it on to.
			"HTTPS_PROXY=" + u.String(),
			"SSL_CERT_FILE=" + bundle,
		}
		out, err := cmd.CombinedOutput()
		return upstream, popups.Asked(), string(out), err
	}

	t.Run("read gets the real token", func(t *testing.T) {
		upstream, asked, out, err := run(t, popup.No, "whoami")
		if err != nil || !strings.Contains(out, "someone") || len(asked) != 0 {
			t.Fatalf("%v %q %+v", err, out, asked)
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
			t.Errorf("asked %+v", asked)
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
