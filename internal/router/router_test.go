package router

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mgnsk/sandbox/internal/apiproxy"
)

// fakeNet is the network the router dials in a test: the two guards (by
// their URL hosts) and every other address, each answering in its own way.
type fakeNet struct {
	t       *testing.T
	mu      sync.Mutex
	connect []string // "guard target auth" per CONNECT a guard got
	fjHosts []string // hosts the Forgejo guard takes
}

func (n *fakeNet) dial(_ context.Context, _, addr string) (net.Conn, error) {
	client, server := net.Pipe()
	switch addr {
	case "gh.guard:1":
		go n.guard(server, "gh", nil)
	case "fj.guard:1":
		go n.guard(server, "fj", n.fjHosts)
	case "down.example:443":
		client.Close()
		server.Close()
		return nil, fmt.Errorf("connection refused")
	default:
		go echo(server, "direct "+addr)
	}
	return client, nil
}

// guard answers one CONNECT like an API guard: 200 and then an echo, or
// StatusNotHandled for a host outside takes (nil: every host).
func (n *fakeNet) guard(conn net.Conn, name string, takes []string) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		conn.Close()
		return
	}
	n.mu.Lock()
	n.connect = append(n.connect, name+" "+req.Host+" "+req.Header.Get("Proxy-Authorization"))
	n.mu.Unlock()
	host, _, _ := net.SplitHostPort(req.Host)
	if takes != nil && !slices.Contains(takes, host) {
		fmt.Fprintf(conn, "HTTP/1.1 %d Not Found\r\nContent-Length: 13\r\n\r\nnot handled\r\n", apiproxy.StatusNotHandled)
		conn.Close()
		return
	}
	fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	echo(&readerConn{Conn: conn, r: br}, name+" "+req.Host)
}

// echo answers each line with prefix and the line.
func echo(conn net.Conn, prefix string) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		fmt.Fprintf(conn, "%s: %s\n", prefix, sc.Text())
	}
}

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// start runs a router with both guards on a real loopback listener.
func start(t *testing.T, n *fakeNet) string {
	t.Helper()
	gh, _ := url.Parse("http://sandbox:ghsecret@gh.guard:1")
	fj, _ := url.Parse("http://sandbox:fjsecret@fj.guard:1")
	r := &Router{Secret: "s3cret", GitHub: gh, Forgejo: fj, Dial: n.dial}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String()
}

// through CONNECTs to target via the router at addr with auth, then sends
// a line; the status line and, after a 200, the answer.
func through(t *testing.T, addr, target, auth string) (string, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if auth != "" {
		fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", auth)
	}
	fmt.Fprint(conn, "\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 512)
		k, _ := resp.Body.Read(body)
		return resp.Status, string(body[:k])
	}
	fmt.Fprint(conn, "ping\n")
	line, _ := br.ReadString('\n')
	return resp.Status, strings.TrimSpace(line)
}

func TestRoutes(t *testing.T) {
	n := &fakeNet{t: t, fjHosts: []string{"codeberg.org"}}
	addr := start(t, n)
	auth := basic("sandbox", "s3cret")
	for _, tc := range []struct{ target, want string }{
		// The GitHub API hosts go to gh-api-proxy, never asking Forgejo's.
		{"api.github.com:443", "gh api.github.com:443: ping"},
		{"uploads.github.com:443", "gh uploads.github.com:443: ping"},
		// A host the Forgejo guard has a token for goes there.
		{"codeberg.org:443", "fj codeberg.org:443: ping"},
		// Everything else is dialed from here, github.com included (git
		// over https, downloads).
		{"github.com:443", "direct github.com:443: ping"},
		{"registry.npmjs.org:443", "direct registry.npmjs.org:443: ping"},
		{"api.github.com:8443", "direct api.github.com:8443: ping"},
	} {
		if status, got := through(t, addr, tc.target, auth); status != "200 Connection Established" || got != tc.want {
			t.Errorf("%s: %s %q, want %q", tc.target, status, got, tc.want)
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	// The guards got their own secrets; Forgejo's was asked for each host
	// GitHub's didn't take.
	want := []string{
		"gh api.github.com:443 " + basic("sandbox", "ghsecret"),
		"gh uploads.github.com:443 " + basic("sandbox", "ghsecret"),
		"fj codeberg.org:443 " + basic("sandbox", "fjsecret"),
		"fj github.com:443 " + basic("sandbox", "fjsecret"),
		"fj registry.npmjs.org:443 " + basic("sandbox", "fjsecret"),
		"fj api.github.com:8443 " + basic("sandbox", "fjsecret"),
	}
	if !slices.Equal(n.connect, want) {
		t.Errorf("guards got\n%q\nwant\n%q", n.connect, want)
	}
}

func TestRefusals(t *testing.T) {
	addr := start(t, &fakeNet{t: t, fjHosts: []string{}})
	for _, tc := range []struct{ target, auth, status, body string }{
		{"example.com:443", "", "407 Proxy Authentication Required", "proxy authentication required"},
		{"example.com:443", basic("sandbox", "wrong"), "407 Proxy Authentication Required", ""},
		{"-bad-.example:443", basic("sandbox", "s3cret"), "400 Bad Request", "bad CONNECT target"},
		{"down.example:443", basic("sandbox", "s3cret"), "502 Bad Gateway", "connection refused"},
	} {
		status, body := through(t, addr, tc.target, tc.auth)
		if status != tc.status || !strings.Contains(body, tc.body) {
			t.Errorf("%s %q: %s %q", tc.target, tc.auth, status, body)
		}
	}

	// Plain HTTP proxying isn't offered.
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: %s", resp.Status)
	}
}

func TestGitHubGuardRefusalIsPassedOn(t *testing.T) {
	n := &fakeNet{t: t}
	gh, _ := url.Parse("http://sandbox:ghsecret@refusing.guard:1")
	r := &Router{Secret: "s", GitHub: gh, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "refusing.guard:1" {
			return n.dial(ctx, network, addr)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = http.ReadRequest(bufio.NewReader(server))
			fmt.Fprint(server, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 6\r\n\r\nno key")
		}()
		return client, nil
	}}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Serve(ctx, ln) }()
	status, body := through(t, ln.Addr().String(), "api.github.com:443", basic("sandbox", "s"))
	if status != "407 Proxy Authentication Required" || !strings.Contains(body, "no key") {
		t.Errorf("%s %q", status, body)
	}
}

func TestCommandEnv(t *testing.T) {
	environ := []string{
		"PATH=/bin",
		"SANDBOX_GH_PROXY=http://sandbox:x@127.0.0.1:1",
		"SANDBOX_FJ_PROXY=http://sandbox:y@127.0.0.1:2",
		"SANDBOX_CA_FILE=/run/ca.pem",
		"SSL_CERT_FILE=/etc/ssl/bundle.crt",
		"NO_PROXY=.corp",
		"HTTPS_PROXY=http://elsewhere",
	}
	got := commandEnv(environ, "http://sandbox:z@127.0.0.1:3")
	want := []string{
		"PATH=/bin",
		"SANDBOX_CA_FILE=/run/ca.pem",
		"HTTPS_PROXY=http://sandbox:z@127.0.0.1:3",
		"NIX_SSL_CERT_FILE=/run/ca.pem",
		"NODE_EXTRA_CA_CERTS=/run/ca.pem",
		"NO_PROXY=.corp,localhost,127.0.0.1,::1",
		"SSL_CERT_FILE=/run/ca.pem",
		"https_proxy=http://sandbox:z@127.0.0.1:3",
		"no_proxy=localhost,127.0.0.1,::1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}

func TestStartWithoutGuards(t *testing.T) {
	environ := []string{"PATH=/bin", "SANDBOX_CA_FILE=/run/ca.pem"}
	got, err := Start(environ)
	if err != nil || !slices.Equal(got, environ) {
		t.Errorf("%q %v", got, err)
	}
}
