package ghproxy

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mgnsk/sandbox/internal/apiproxy/apiproxytest"
	"github.com/mgnsk/sandbox/internal/popup"
)

const projectToken = "github_pat_project0123"

func graphql(t *testing.T, query string, extra ...any) []byte {
	t.Helper()
	req := map[string]any{"query": query}
	for i := 0; i < len(extra); i += 2 {
		req[extra[i].(string)] = extra[i+1]
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func describeBody(t *testing.T, method, path string, body []byte) string {
	t.Helper()
	r := httptest.NewRequest(method, "https://api.github.com"+path, bytes.NewReader(body))
	description, err := describe(r, apiHost)
	if err != nil {
		t.Fatal(err)
	}
	return description
}

func TestRESTReadsAndWrites(t *testing.T) {
	for _, method := range []string{"GET", "HEAD"} {
		if d := describeBody(t, method, "/repos/o/r/pulls", nil); d != "" {
			t.Errorf("%s asks: %q", method, d)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if d := describeBody(t, method, "/repos/o/r/labels", nil); d != method+" api.github.com/repos/o/r/labels" {
			t.Errorf("%s: %q", method, d)
		}
	}
	r := httptest.NewRequest("POST", "https://uploads.github.com/repos/o/r/releases/1/assets", strings.NewReader("x"))
	if d, _ := describe(r, "uploads.github.com"); d != "POST uploads.github.com/repos/o/r/releases/1/assets" {
		t.Errorf("upload: %q", d)
	}
}

func TestGraphQLQueriesNeedNoPopup(t *testing.T) {
	for _, query := range []string{
		"{ viewer { login } }",
		"query Q { viewer { login } }",
		"query Q($n: Int) { viewer { repositories(first: $n) { totalCount } } }",
		"fragment F on User { login } query { viewer { ...F } }",
		"query A { viewer { login } } query B { rateLimit { remaining } }",
	} {
		if d := describeBody(t, "POST", "/graphql", graphql(t, query)); d != "" {
			t.Errorf("%s asks: %q", query, d)
		}
	}
}

func TestGraphQLMutationsAndSubscriptionsNeedAPopup(t *testing.T) {
	for _, query := range []string{
		`mutation { addStar(input: {starrableId: "x"}) { clientMutationId } }`,
		"subscription { viewer { login } }",
		// A mutation anywhere in the document counts, whichever operation
		// operationName selects.
		"query A { viewer { login } } mutation B { addStar(input: {}) { clientMutationId } }",
	} {
		if d := describeBody(t, "POST", "/graphql", graphql(t, query, "operationName", "A")); d == "" {
			t.Errorf("%s doesn't ask", query)
		}
	}
	// Over GET, even a query asks.
	if d := describeBody(t, "GET", "/graphql", nil); d == "" {
		t.Error("GET /graphql doesn't ask")
	}
}

func TestUnparseableGraphQLNeedsAPopup(t *testing.T) {
	batched, _ := json.Marshal([]any{map[string]string{"query": "{ viewer { login } }"}})
	for name, body := range map[string][]byte{
		"empty":            nil,
		"not json":         []byte("not json"),
		"not utf-8":        {0xff, 0xfe},
		"empty list":       []byte("[]"),
		"batched":          batched,
		"no query":         []byte(`{"variables": {}}`),
		"query not string": []byte(`{"query": 1}`),
		"duplicate query":  []byte(`{"query": "{ viewer { login } }", "query": "mutation { x }"}`),
		"syntax error":     graphql(t, "{ viewer { login }"),
		"no operation":     graphql(t, "fragment F on User { login }"),
		"too deep":         graphql(t, strings.Repeat("{", 20000)+strings.Repeat("}", 20000)),
	} {
		if d := describeBody(t, "POST", "/graphql", body); !strings.HasSuffix(d, "(not a GraphQL request this proxy understands)") {
			t.Errorf("%s: %q", name, d)
		}
	}
}

// Operations with their top-level fields (not aliases), and variables as
// sent: key order kept, indented, non-ASCII as it is.
func TestGraphQLPopupText(t *testing.T) {
	query := "query Q { viewer { login } } " +
		"mutation { first: addStar(input: {}) { clientMutationId } " +
		"...F removeStar(input: {}) { clientMutationId } } " +
		"fragment F on Mutation { x }"
	body := []byte(`{"query": ` + string(must(json.Marshal(query))) + `, "variables": {"z": {"nested": [1, -2, 1.5, true, false, null], "empty": {}}, "a": "quote \" ctl \u0001 日本"}}`)
	want := "POST api.github.com/graphql\n\n" +
		"query Q: viewer\n" +
		"mutation (anonymous): addStar, removeStar\n\n" +
		"variables:\n" +
		"{\n" +
		"  \"z\": {\n" +
		"    \"nested\": [\n      1,\n      -2,\n      1.5,\n      true,\n      false,\n      null\n    ],\n" +
		"    \"empty\": {}\n" +
		"  },\n" +
		"  \"a\": \"quote \\\" ctl \\u0001 日本\"\n" +
		"}"
	if got := describeBody(t, "POST", "/graphql", body); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestEmptyVariablesAreNotShown(t *testing.T) {
	for _, variables := range []any{nil, map[string]any{}, []any{}, 0, "", false} {
		body := graphql(t, "mutation { addStar(input: {}) { clientMutationId } }", "variables", variables)
		if d := describeBody(t, "POST", "/graphql", body); strings.Contains(d, "variables:") {
			t.Errorf("%v shown: %q", variables, d)
		}
	}
}

func TestTunnel(t *testing.T) {
	for hostport, want := range map[string]bool{
		"github.com:443":                                 true,
		"codeload.github.com:443":                        true,
		"objects.githubusercontent.com:443":              true,
		"productionresultssa0.blob.core.windows.net:443": true,
		"api.github.com:443":                             false,
		"uploads.github.com:443":                         false,
		"github.com:22":                                  false,
		"example.com:443":                                false,
		"githubusercontent.com.example.com:443":          false,
	} {
		if got := tunnel(hostport); got != want {
			t.Errorf("tunnel(%s) = %v", hostport, got)
		}
	}
}

func TestTokens(t *testing.T) {
	upstream := apiproxytest.NewUpstream(t)
	// A gh logged in on the host is never asked.
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\necho gho_host0123456\n"), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	auth := func(token string) (int, string) {
		p := New(token)
		upstream.Wire(p)
		h, u := apiproxytest.ServeHTTPS(t, p)
		resp, err := apiproxytest.Client(h, u).Get("https://api.github.com/user")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if seen := upstream.Seen(); resp.StatusCode == 200 {
			return 200, seen[len(seen)-1].Header.Get("Authorization")
		}
		return resp.StatusCode, ""
	}
	if status, _ := auth(""); status != 403 {
		t.Errorf("no token: %d", status)
	}
	if _, got := auth(projectToken); got != "token "+projectToken {
		t.Errorf("token: %q", got)
	}
}

// -- end to end, with a real gh --

// gh runs gh from PATH, through a fresh gh-api-proxy to a stand-in for
// GitHub, with the proxy settings the sandbox's router hands it on to; its
// output, stderr and popups.
func gh(t *testing.T, upstream *apiproxytest.Upstream, answer popup.Answer, args ...string) (stdout, stderr string, asked []popup.Request, err error) {
	t.Helper()
	dir := t.TempDir()
	popups := &apiproxytest.Popups{Answer: answer}
	p := New(projectToken)
	p.Ask = popups.Ask
	upstream.Wire(p)
	h, u := apiproxytest.ServeHTTPS(t, p)
	bundle := filepath.Join(dir, "bundle.pem")
	os.WriteFile(bundle, []byte(h.Info().CA), 0o600)

	cmd := exec.Command("gh", args...)
	home := filepath.Join(dir, "home")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + home + "/config",
		"XDG_CACHE_HOME=" + home + "/cache",
		"XDG_STATE_HOME=" + home + "/state",
		"GH_TOKEN=placeholder",
		"GH_NO_UPDATE_NOTIFIER=1",
		"GH_TELEMETRY=false",
		"HTTPS_PROXY=" + u.String(),
		"SSL_CERT_FILE=" + bundle,
	}
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), popups.Asked(), err
}

func github(w http.ResponseWriter, r *http.Request) {
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		json.MarshalWrite(w, v)
	}
	switch path := r.URL.Path; {
	case path == "/user":
		reply(200, map[string]string{"login": "someone"})
	case path == "/graphql":
		reply(200, map[string]any{"data": map[string]any{"viewer": map[string]string{"login": "someone"}}})
	case strings.HasPrefix(path, "/repos/o/r/releases/tags/v1"):
		reply(200, map[string]any{"id": 1, "tag_name": "v1", "assets": []any{},
			"upload_url": "https://uploads.github.com/repos/o/r/releases/1/assets{?name,label}"})
	case strings.HasPrefix(path, "/repos/o/r/releases/1/assets") && r.Method == "GET":
		reply(200, []any{})
	case strings.HasPrefix(path, "/repos/o/r/releases/1/assets"):
		reply(201, map[string]any{"id": 5, "name": "asset.txt", "state": "uploaded"})
	case path == "/repos/o/r/labels" && r.Method == "POST":
		reply(201, map[string]string{"name": "x"})
	default:
		reply(404, map[string]string{"message": "Not Found"})
	}
}

func TestGh(t *testing.T) {
	if _, err := exec.LookPath("gh"); err != nil {
		t.Skip("needs gh on PATH")
	}
	newUpstream := func() *apiproxytest.Upstream {
		u := apiproxytest.NewUpstream(t)
		u.Handler = github
		return u
	}

	t.Run("REST read uses the real token", func(t *testing.T) {
		u := newUpstream()
		out, errOut, asked, err := gh(t, u, popup.No, "api", "user", "--jq", ".login")
		if err != nil || strings.TrimSpace(out) != "someone" || len(asked) != 0 {
			t.Fatalf("%v %q %q %v", err, out, errOut, asked)
		}
		if s := u.Seen(); len(s) != 1 || s[0].Host != "api.github.com" || s[0].Header.Get("Authorization") != "token "+projectToken {
			t.Errorf("upstream got %+v", s)
		}
	})
	t.Run("GraphQL query asks nothing", func(t *testing.T) {
		out, errOut, asked, err := gh(t, newUpstream(), popup.No, "api", "graphql", "-f", "query={ viewer { login } }", "--jq", ".data.viewer.login")
		if err != nil || strings.TrimSpace(out) != "someone" || len(asked) != 0 {
			t.Fatalf("%v %q %q %v", err, out, errOut, asked)
		}
	})
	t.Run("declined write fails and never reaches GitHub", func(t *testing.T) {
		u := newUpstream()
		_, errOut, asked, err := gh(t, u, popup.No, "api", "-X", "POST", "repos/o/r/labels", "-f", "name=x")
		if err == nil || !strings.Contains(errOut, "declined by user") || len(u.Seen()) != 0 {
			t.Fatalf("%v %q %+v", err, errOut, u.Seen())
		}
		if len(asked) != 1 || !strings.Contains(asked[0].Text, "POST api.github.com/repos/o/r/labels") {
			t.Errorf("asked %q", asked)
		}
	})
	t.Run("approved write goes through", func(t *testing.T) {
		u := newUpstream()
		if _, errOut, _, err := gh(t, u, popup.Once, "api", "-X", "POST", "repos/o/r/labels", "-f", "name=x"); err != nil {
			t.Fatalf("%v %q", err, errOut)
		}
		if s := u.Seen(); len(s) != 1 || string(s[0].Body) != `{"name":"x"}` {
			t.Errorf("upstream got %+v", s)
		}
	})
	t.Run("release upload", func(t *testing.T) {
		u := newUpstream()
		asset := filepath.Join(t.TempDir(), "asset.txt")
		payload := strings.Repeat("payload", 1000)
		os.WriteFile(asset, []byte(payload), 0o600)
		_, errOut, asked, err := gh(t, u, popup.Always, "release", "upload", "v1", asset, "-R", "o/r")
		if err != nil {
			t.Fatalf("%v %q", err, errOut)
		}
		var uploads []apiproxytest.Seen
		for _, s := range u.Seen() {
			if s.Host == "uploads.github.com" {
				uploads = append(uploads, s)
			}
		}
		if len(uploads) != 1 || uploads[0].Method != "POST" || string(uploads[0].Body) != payload ||
			uploads[0].Header.Get("Authorization") != "token "+projectToken {
			t.Errorf("uploads %+v", uploads)
		}
		if len(asked) != 1 {
			t.Errorf("asked %d times", len(asked))
		}
	})
}
