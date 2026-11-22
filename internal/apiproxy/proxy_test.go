package apiproxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/apiproxy/apiproxytest"
	"github.com/mgnsk/sandbox/internal/popup"
)

const token = "real-token-0123"

// testGuard forwards to api.example and up.example with a token, tunnels
// tunnel.example, and lets only paths under /ok through.
func testGuard() apiproxy.Guard {
	return apiproxy.Guard{
		Name:  "test-proxy",
		Title: "Allow it?",
		Route: func(host string) (apiproxy.Route, error) {
			if host != "api.example" && host != "up.example:8443" {
				return apiproxy.Route{}, fmt.Errorf("host not allowed: %s", host)
			}
			return apiproxy.Route{Host: host, Header: http.Header{"Authorization": {"token " + token}}}, nil
		},
		AllowPath:   func(path string) bool { return strings.HasPrefix(path, "/ok") },
		Tunnel:      func(hostport string) bool { return hostport == "tunnel.example:443" },
		DropHeaders: []string{"X-Secret"},
	}
}

type world struct {
	upstream *apiproxytest.Upstream
	popups   *apiproxytest.Popups
	proxy    *apiproxy.Proxy
}

func newWorld(t *testing.T) *world {
	w := &world{upstream: apiproxytest.NewUpstream(t), popups: &apiproxytest.Popups{}}
	w.proxy = &apiproxy.Proxy{Guard: testGuard(), Ask: w.popups.Ask}
	w.upstream.Wire(w.proxy)
	return w
}

// https serves the proxy as an HTTPS proxy; a client through it.
func (w *world) https(t *testing.T) (*http.Client, *apiproxy.HTTPS, *url.URL) {
	h, u := apiproxytest.ServeHTTPS(t, w.proxy)
	return apiproxytest.Client(h, u), h, u
}

func do(t *testing.T, c *http.Client, method, rawURL string, body io.Reader, header ...string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token placeholder")
	for i := 0; i < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func message(t *testing.T, body []byte) string {
	t.Helper()
	var m struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("not a refusal: %q", body)
	}
	return m.Message
}

func (w *world) refused(t *testing.T, resp *http.Response, body []byte, status int, want string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("status %d, want %d: %s", resp.StatusCode, status, body)
	}
	if got := message(t, body); !strings.HasPrefix(got, "test-proxy: ") || !strings.Contains(got, want) {
		t.Errorf("message %q, want %q", got, want)
	}
	if seen := w.upstream.Seen(); len(seen) != 0 {
		t.Errorf("reached upstream: %+v", seen)
	}
}

func TestReadsAreForwardedWithTheRealToken(t *testing.T) {
	w := newWorld(t)
	c, _, _ := w.https(t)
	resp, body := do(t, c, "GET", "https://api.example/ok/user?x=1", nil, "X-Custom", "kept", "X-Secret", "dropped", "Connection", "keep-alive")
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"/ok/user?x=1"`)) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	seen := w.upstream.Seen()
	if len(seen) != 1 {
		t.Fatalf("seen %+v", seen)
	}
	s := seen[0]
	if s.Host != "api.example" || s.Header.Get("Authorization") != "token "+token || s.Header.Get("X-Custom") != "kept" {
		t.Errorf("upstream got %+v", s)
	}
	if s.Header.Get("X-Secret") != "" || s.Header.Get("Proxy-Authorization") != "" {
		t.Errorf("credential headers forwarded: %v", s.Header)
	}
	if len(w.popups.Asked()) != 0 {
		t.Error("a read asked")
	}
}

// What would have the real host see another request than the one judged
// here never gets there.
func TestUpgradesAndMethodOverridesAreNotForwarded(t *testing.T) {
	w := newWorld(t)
	c, _, _ := w.https(t)
	resp, body := do(t, c, "GET", "https://api.example/ok/user", nil, "Connection", "Upgrade", "Upgrade", "websocket")
	w.refused(t, resp, body, 501, "protocol upgrades aren't forwarded")
	if resp, _ := do(t, c, "GET", "https://api.example/ok/user", nil,
		"X-HTTP-Method-Override", "DELETE", "X-HTTP-Method", "DELETE", "X-Method-Override", "DELETE"); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	seen := w.upstream.Seen()
	if len(seen) != 1 {
		t.Fatalf("seen %+v", seen)
	}
	for name := range seen[0].Header {
		if strings.Contains(strings.ToLower(name), "method") {
			t.Errorf("%s forwarded", name)
		}
	}
}

func TestWritesAsk(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			w := newWorld(t)
			c, _, _ := w.https(t)
			resp, body := do(t, c, method, "https://api.example/ok/labels", strings.NewReader(`{"name":"bug"}`))
			w.refused(t, resp, body, 403, "declined by user")
			// With what it would write: the path alone doesn't say.
			want := []popup.Request{{Name: "test-proxy", Text: "Allow it?\n\n" + method + " api.example/ok/labels\n\n{\n  \"name\": \"bug\"\n}\n"}}
			if got := w.popups.Asked(); !slices.Equal(got, want) {
				t.Errorf("asked %+v", got)
			}
		})
	}
}

func TestApprovedWritesGoThrough(t *testing.T) {
	w := newWorld(t)
	c, _, _ := w.https(t)
	w.popups.Answer = popup.Once
	payload := bytes.Repeat([]byte{0, 1, 2, 255}, 1<<18)
	for range 2 {
		if resp, body := do(t, c, "POST", "https://up.example:8443/ok/assets", bytes.NewReader(payload)); resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	}
	if n := len(w.popups.Asked()); n != 2 {
		t.Errorf("once asked %d times", n)
	}
	for _, s := range w.upstream.Seen() {
		if !bytes.Equal(s.Body, payload) || s.Host != "up.example:8443" || s.Header.Get("Authorization") != "token "+token {
			t.Errorf("upstream got %s %s, %d bytes", s.Host, s.Header, len(s.Body))
		}
	}

	w.popups.Answer = popup.Always
	do(t, c, "DELETE", "https://api.example/ok/x", nil)
	w.popups.Answer = popup.No
	if resp, _ := do(t, c, "DELETE", "https://api.example/ok/y", nil); resp.StatusCode != 200 {
		t.Errorf("always didn't cover the next write: %d", resp.StatusCode)
	}
	if n := len(w.popups.Asked()); n != 3 {
		t.Errorf("asked %d times", n)
	}
}

func TestRefusals(t *testing.T) {
	w := newWorld(t)
	c, _, _ := w.https(t)
	resp, body := do(t, c, "GET", "https://other.example/ok", nil)
	w.refused(t, resp, body, 403, "host not allowed: other.example")
	resp, body = do(t, c, "GET", "https://api.example/nope", nil)
	w.refused(t, resp, body, 403, "path not allowed: /nope")
	resp, body = do(t, c, "PROPFIND", "https://api.example/ok", nil)
	w.refused(t, resp, body, 501, "unsupported method (PROPFIND)")
}

func TestPopupTextIsCleanedNotTruncated(t *testing.T) {
	w := newWorld(t)
	c, _, _ := w.https(t)
	long := strings.Repeat("x", 5000)
	do(t, c, "DELETE", "https://api.example/ok/%1b[31m/"+long, nil)
	asked := w.popups.Asked()
	if len(asked) != 1 || strings.Contains(asked[0].Text, "\x1b") || !strings.Contains(asked[0].Text, long) {
		t.Errorf("asked %+v", asked)
	}
}

func TestResponses(t *testing.T) {
	w := newWorld(t)
	big := bytes.Repeat([]byte("x"), 1<<20+7)
	w.upstream.Handler = func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok/big":
			rw.Write(big) // Chunked: no Content-Length.
		case "/ok/redirect":
			http.Redirect(rw, r, "https://objects.example/asset", http.StatusFound)
		default:
			rw.Header().Set("Content-Length", "5")
			io.WriteString(rw, "hello")
		}
	}
	c, _, _ := w.https(t)
	if resp, body := do(t, c, "GET", "https://api.example/ok/big", nil); resp.StatusCode != 200 || !bytes.Equal(body, big) {
		t.Errorf("big: %d, %d bytes", resp.StatusCode, len(body))
	}
	if resp, _ := do(t, c, "GET", "https://api.example/ok/redirect", nil); resp.StatusCode != 302 || resp.Header.Get("Location") != "https://objects.example/asset" {
		t.Errorf("redirect: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, body := do(t, c, "HEAD", "https://api.example/ok/x", nil); resp.StatusCode != 200 || resp.ContentLength != 5 || len(body) != 0 {
		t.Errorf("head: %d %d %q", resp.StatusCode, resp.ContentLength, body)
	}
}

func TestEventStreamsAreRelayedAsTheyArrive(t *testing.T) {
	w := newWorld(t)
	release := make(chan struct{})
	w.upstream.Handler = func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(rw, "event: one\n\n")
		rw.(http.Flusher).Flush()
		<-release
		io.WriteString(rw, "event: two\n\n")
	}
	c, _, _ := w.https(t)
	resp, err := c.Get("https://api.example/ok/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, len("event: one\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "event: one\n\n" {
		t.Fatalf("first event: %q, %v", first, err)
	}
	close(release)
	if rest, _ := io.ReadAll(resp.Body); string(rest) != "event: two\n\n" {
		t.Errorf("second event: %q", rest)
	}
}

func TestUpstreamErrorsAre502(t *testing.T) {
	w := newWorld(t)
	w.proxy.Transport = &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unreachable") },
	}
	c, _, _ := w.https(t)
	resp, body := do(t, c, "GET", "https://api.example/ok", nil)
	if resp.StatusCode != 502 || !strings.Contains(message(t, body), "upstream error") {
		t.Errorf("%d %s", resp.StatusCode, body)
	}

	// Upstream's certificate is checked like the real host's would be.
	other := apiproxytest.NewUpstream(t)
	w = newWorld(t)
	w.proxy.Transport.(*http.Transport).TLSClientConfig.RootCAs = other.Pool()
	c, _, _ = w.https(t)
	if resp, _ := do(t, c, "GET", "https://api.example/ok", nil); resp.StatusCode != 502 {
		t.Errorf("untrusted upstream: %d", resp.StatusCode)
	}
}

func TestReadBodyLimit(t *testing.T) {
	w := newWorld(t)
	w.proxy.Describe = func(r *http.Request, _ string) (string, error) {
		_, err := apiproxy.ReadBody(r, 10)
		return "", err
	}
	c, _, _ := w.https(t)
	resp, body := do(t, c, "POST", "https://api.example/ok", strings.NewReader("12345678901"))
	w.refused(t, resp, body, 413, "too large")
	// Chunked, without a Content-Length.
	resp, body = do(t, c, "POST", "https://api.example/ok", io.MultiReader(strings.NewReader("123456"), strings.NewReader("78901")))
	w.refused(t, resp, body, 413, "too large")
	if resp, _ := do(t, c, "POST", "https://api.example/ok", strings.NewReader("1234567890")); resp.StatusCode != 200 {
		t.Errorf("at the limit: %d", resp.StatusCode)
	}
	if s := w.upstream.Seen(); len(s) != 1 || string(s[0].Body) != "1234567890" {
		t.Errorf("body read for classifying not forwarded: %+v", s)
	}
}

// roundTripFunc is a function as an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A body read for the popup reaches the transport with GetBody, so a request
// on an HTTP/2 connection the host shuts down (GOAWAY) after the body was
// sent is retried on a new one instead of failing.
func TestReadBodiesCanBeSentAgain(t *testing.T) {
	w := newWorld(t)
	w.popups.Answer = popup.Always
	upstream := w.proxy.Transport
	var replayed [][]byte
	w.proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody == nil {
			t.Errorf("%s %s: no GetBody", r.Method, r.URL)
		} else {
			for range 2 {
				body, _ := r.GetBody()
				data, _ := io.ReadAll(body)
				replayed = append(replayed, data)
			}
		}
		return upstream.RoundTrip(r)
	})
	c, _, _ := w.https(t)
	payload := `{"title": "x"}`
	if resp, body := do(t, c, "POST", "https://api.example/ok/issues", strings.NewReader(payload),
		"Content-Type", "application/json"); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if len(replayed) != 2 || string(replayed[0]) != payload || string(replayed[1]) != payload {
		t.Errorf("replayed %q", replayed)
	}
	if s := w.upstream.Seen(); len(s) != 1 || string(s[0].Body) != payload {
		t.Errorf("upstream got %+v", s)
	}
}

// -- the HTTPS proxy itself --

// connect CONNECTs to target through the proxy at u with auth as
// Proxy-Authorization; the connection and the answer.
func connect(t *testing.T, u *url.URL, target, auth string) (net.Conn, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if auth != "" {
		fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", auth)
	}
	io.WriteString(conn, "\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	return conn, resp
}

func basic(u *url.URL) string {
	secret, _ := u.User.Password()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("sandbox:"+secret))
}

func TestConnectNeedsTheSecret(t *testing.T) {
	w := newWorld(t)
	_, _, u := w.https(t)
	for _, auth := range []string{"", "Basic " + base64.StdEncoding.EncodeToString([]byte("sandbox:wrong"))} {
		_, resp := connect(t, u, "api.example:443", auth)
		if resp.StatusCode != 407 || !strings.HasPrefix(resp.Header.Get("Proxy-Authenticate"), "Basic") {
			t.Errorf("auth %q: %d %v", auth, resp.StatusCode, resp.Header)
		}
	}
}

func TestBadConnectTargets(t *testing.T) {
	w := newWorld(t)
	_, _, u := w.https(t)
	for _, target := range []string{"api.example", "[::1]:443", "x:0", "x:70000", "api.example.:443", "a_b:443"} {
		if _, resp := connect(t, u, target, basic(u)); resp.StatusCode != 400 {
			t.Errorf("%s: %d", target, resp.StatusCode)
		}
	}
}

func TestPlainProxyingIsRefused(t *testing.T) {
	w := newWorld(t)
	_, _, u := w.https(t)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}).Get("http://api.example/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Errorf("status %d", resp.StatusCode)
	}
}

// A tunneled host gets the client's own TLS, end to end: its own
// Authorization arrives, and no token is added.
func TestTunnelsAreUnread(t *testing.T) {
	w := newWorld(t)
	_, _, u := w.https(t)
	c := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{RootCAs: w.upstream.Pool()},
	}}
	resp, body := do(t, c, "GET", "https://tunnel.example/anything", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if s := w.upstream.Seen(); len(s) != 1 || s[0].Header.Get("Authorization") != "token placeholder" {
		t.Errorf("upstream got %+v", s)
	}
}

// Every proxy makes its own CA; one's isn't trusted for another.
func TestEachProxyHasItsOwnCA(t *testing.T) {
	w := newWorld(t)
	_, a, _ := w.https(t)
	_, b, u := w.https(t)
	if a.Info().CA == b.Info().CA || a.Info().Secret == b.Info().Secret {
		t.Fatal("shared CA or secret")
	}
	conn, resp := connect(t, u, "api.example:443", basic(u))
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %d", resp.StatusCode)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(a.Info().CA))
	var unknown x509.UnknownAuthorityError
	if err := tls.Client(conn, &tls.Config{ServerName: "api.example", RootCAs: pool}).Handshake(); !errors.As(err, &unknown) {
		t.Errorf("handshake with the other CA: %v", err)
	}
}

// inTunnel sends raw inside a tunnel to target the proxy ends itself; the
// answer.
func inTunnel(t *testing.T, h *apiproxy.HTTPS, u *url.URL, target, raw string) *http.Response {
	t.Helper()
	conn, resp := connect(t, u, target, basic(u))
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %d", resp.StatusCode)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(h.Info().CA))
	name, _, _ := net.SplitHostPort(target)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: name, RootCAs: pool})
	if _, err := io.WriteString(tlsConn, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestRequestsInATunnel(t *testing.T) {
	for name, tc := range map[string]struct {
		raw    string
		status int
	}{
		"other host":     {"GET /ok HTTP/1.1\r\nHost: up.example:8443\r\n\r\n", 421},
		"two hosts":      {"GET /ok HTTP/1.1\r\nHost: api.example\r\nHost: up.example\r\n\r\n", 400},
		"two lengths":    {"GET /ok HTTP/1.1\r\nHost: api.example\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n", 400},
		"bad length":     {"GET /ok HTTP/1.1\r\nHost: api.example\r\nContent-Length: x\r\n\r\n", 400},
		"absolute form":  {"GET https://api.example/ok HTTP/1.1\r\nHost: api.example\r\n\r\n", 400},
		"connect inside": {"CONNECT api.example:443 HTTP/1.1\r\nHost: api.example\r\n\r\n", 501},
		"http2":          {"GET /ok HTTP/2.0\r\nHost: api.example\r\n\r\n", 505},
		"header too long": {"GET /ok HTTP/1.1\r\nHost: api.example\r\nX-A: " +
			strings.Repeat("a", 2<<20) + "\r\n\r\n", 431},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			_, h, u := w.https(t)
			if resp := inTunnel(t, h, u, "api.example:443", tc.raw); resp.StatusCode != tc.status {
				t.Errorf("status %d, want %d", resp.StatusCode, tc.status)
			}
			if s := w.upstream.Seen(); len(s) != 0 {
				t.Errorf("reached upstream: %+v", s)
			}
		})
	}
}

func TestOnAUnixSocket(t *testing.T) {
	w := newWorld(t)
	path := filepath.Join(t.TempDir(), "api.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- w.proxy.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()

	// As curl sends large bodies: the body only after a 100.
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	w.popups.Answer = popup.Once
	io.WriteString(conn, "POST /ok HTTP/1.1\r\nHost: api.example\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n")
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if line, _ := br.ReadString('\n'); line != "HTTP/1.1 100 Continue\r\n" {
		t.Fatalf("interim %q", line)
	}
	br.ReadString('\n')
	io.WriteString(conn, "{}")
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	s := w.upstream.Seen()
	if len(s) != 1 || string(s[0].Body) != "{}" || s[0].Header.Get("Expect") != "" {
		t.Errorf("upstream got %+v", s)
	}
}
