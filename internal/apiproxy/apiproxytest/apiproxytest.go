// Package apiproxytest stands in for what an API guard talks to in tests:
// the real hosts, over TLS, and the launcher's popups.
package apiproxytest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/mitmca"
	"github.com/mgnsk/sandbox/internal/popup"
)

// Seen is a request that reached the upstream.
type Seen struct {
	Method, Host, Path string // Path with its query.
	Header             http.Header
	Body               []byte
}

// Upstream is every real host at once, over TLS with certificates from its
// own CA. Handler answers what it gets, after it's recorded; by default
// with {"path": ...}.
type Upstream struct {
	Server  *httptest.Server
	CA      *mitmca.CA
	Handler http.HandlerFunc

	mu   sync.Mutex
	seen []Seen
}

// NewUpstream starts an Upstream, closed with the test.
func NewUpstream(t testing.TB) *Upstream {
	t.Helper()
	ca, err := mitmca.New("test upstream")
	if err != nil {
		t.Fatal(err)
	}
	u := &Upstream{CA: ca}
	u.Server = httptest.NewUnstartedServer(http.HandlerFunc(u.serve))
	u.Server.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cfg, err := ca.Config(hello.ServerName)
		if err != nil {
			return nil, err
		}
		return &cfg.Certificates[0], nil
	}}
	u.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	u.Server.StartTLS()
	t.Cleanup(u.Server.Close)
	return u
}

func (u *Upstream) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.seen = append(u.seen, Seen{r.Method, r.Host, r.RequestURI, r.Header.Clone(), body})
	u.mu.Unlock()
	if u.Handler != nil {
		u.Handler(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, map[string]string{"path": r.RequestURI})
}

// Seen is every request so far.
func (u *Upstream) Seen() []Seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]Seen(nil), u.seen...)
}

// Pool trusts the upstream's CA.
func (u *Upstream) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(u.CA.PEM())
	return pool
}

// Dial connects to the upstream whatever the address.
func (u *Upstream) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, u.Server.Listener.Addr().String())
}

// Wire has p reach its hosts at u, checking their certificates against u's
// CA as the real hosts' would be.
func (u *Upstream) Wire(p *apiproxy.Proxy) {
	p.Transport = &http.Transport{
		DialContext:     u.Dial,
		TLSClientConfig: &tls.Config{RootCAs: u.Pool()},
	}
	p.Dial = u.Dial
}

// Popups are the launcher's: each request is recorded and answered with
// Answer.
type Popups struct {
	Answer popup.Answer
	mu     sync.Mutex
	asked  []popup.Request
}

// Ask is a guard's popup.Ask.
func (p *Popups) Ask(name, text string) popup.Answer {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, popup.Request{Name: name, Text: text})
	if p.Answer == "" {
		return popup.No
	}
	return p.Answer
}

// Asked is every request so far.
func (p *Popups) Asked() []popup.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]popup.Request(nil), p.asked...)
}

// ServeHTTPS serves p as an HTTPS proxy on a loopback port for the test;
// the proxy and its URL, with the secret.
func ServeHTTPS(t testing.TB, p *apiproxy.Proxy) (*apiproxy.HTTPS, *url.URL) {
	t.Helper()
	h, err := apiproxy.NewHTTPS(p)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return h, &url.URL{Scheme: "http", User: url.UserPassword("sandbox", h.Info().Secret), Host: ln.Addr().String()}
}

// Client is an HTTP client through the proxy at proxyURL, trusting its CA
// alone, as the sandbox's gh and fj do.
func Client(h *apiproxy.HTTPS, proxyURL *url.URL) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(h.Info().CA))
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
