package apiproxy

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mgnsk/sandbox/internal/mitmca"
)

// host:port, as a client CONNECTs to it. No IPv6 literals.
var connectRE = regexp.MustCompile(`^([a-z0-9.-]+):([0-9]{1,5})$`)

// HTTPSProxy is a guard as an intercepting HTTPS_PROXY on the host's
// loopback. The peer is pasta, so its popup can't name the requesting
// process.
type HTTPSProxy struct {
	server
	ln       net.Listener
	ca       *mitmca.CA
	secret   string
	expected []byte
}

// NewHTTPSProxy listens on a free loopback port with a fresh CA and secret.
func NewHTTPSProxy(policy Policy) (*HTTPSProxy, error) {
	ca, err := mitmca.New("sandbox " + policy.Name())
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	token := base64.StdEncoding.EncodeToString([]byte("sandbox:" + secret))
	return &HTTPSProxy{
		server:   server{policy: policy},
		ln:       ln,
		ca:       ca,
		secret:   secret,
		expected: []byte("Basic " + token),
	}, nil
}

// Announce writes ca.pem, then proxy.json ({"port", "secret"}) - the
// launcher waits for the latter. stateDir is private to the launcher's
// user.
func (p *HTTPSProxy) Announce(stateDir string) error {
	if err := os.WriteFile(filepath.Join(stateDir, "ca.pem"), p.ca.PEM(), 0o666); err != nil {
		return err
	}
	port := p.ln.Addr().(*net.TCPAddr).Port
	info := fmt.Sprintf(`{"port": %d, "secret": %s}`, port, strconv.Quote(p.secret))
	tmp := filepath.Join(stateDir, ".proxy.json")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(info); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir, "proxy.json"))
}

// Serve answers connections until the listener fails.
func (p *HTTPSProxy) Serve() error {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			p.handleConnect(conn)
			closeWrite(conn)
		}()
	}
}

// authorized says whether Proxy-Authorization (all its values) carries the
// secret.
func (p *HTTPSProxy) authorized(values []string) bool {
	return len(values) == 1 &&
		subtle.ConstantTimeCompare([]byte(pyStrip(values[0])), p.expected) == 1
}

// bufConn reads what a bufio.Reader already holds before the connection.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// handleConnect answers a CONNECT, then the TLS handshake inside it with a
// certificate for the target, and the one request in the tunnel.
func (p *HTTPSProxy) handleConnect(raw net.Conn) {
	conn := &timeoutConn{raw, requestTimeout}
	br := bufio.NewReader(conn)
	r := p.readOne(br, conn)
	if r == nil {
		return
	}
	switch {
	case isProxied(r.method):
		// Plain-HTTP proxying isn't offered: everything goes over CONNECT.
		p.refuse(conn, http.StatusMethodNotAllowed, "only CONNECT")
		return
	case r.method != "CONNECT":
		p.refuse(conn, http.StatusNotImplemented, "unsupported method ("+clean(latin1(r.method))+")")
		return
	case !p.authorized(r.all("proxy-authorization")):
		p.refuse(conn, http.StatusProxyAuthRequired, "proxy authentication required",
			header{"Proxy-Authenticate", `Basic realm="sandbox"`})
		return
	}
	match := connectRE.FindStringSubmatch(asciiLower(r.path))
	var port int
	if match != nil {
		port, _ = strconv.Atoi(match[2])
	}
	// A trailing dot: Go's TLS refuses one in SNI, so refused up front.
	if match == nil || strings.HasSuffix(match[1], ".") || port < 1 || port > 65535 {
		p.refuse(conn, http.StatusBadRequest, "bad CONNECT target: "+clean(latin1(r.path)))
		return
	}
	name, portText := match[1], match[2]
	host := name
	if portText != "443" {
		host = name + ":" + portText
	}
	client := &bufConn{conn, br}
	if p.policy.TunnelAllowed(host) {
		p.tunnel(client, name, strconv.Itoa(port))
		return
	}

	cfg, err := p.ca.Config(name)
	if err != nil {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	tlsConn := tls.Server(client, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return // Client gone, or didn't trust the certificate.
	}
	p.handle(tlsConn, bufio.NewReader(tlsConn), host)
	// With a close_notify: responses here are close-delimited, and rustls
	// (fj) takes an EOF without one as a truncated body.
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tlsConn.CloseWrite()
}

// tunnel connects the client to the real host, without looking inside.
func (p *HTTPSProxy) tunnel(client net.Conn, name, port string) {
	dialer := &net.Dialer{Timeout: upstreamTimeout}
	up, err := dialer.Dial("tcp", upstreamAddress(name, port))
	if err != nil {
		p.refuse(client, http.StatusBadGateway, fmt.Sprintf("upstream error: %v", err))
		return
	}
	defer up.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	relay(&timeoutConn{client, upstreamTimeout}, &timeoutConn{up, upstreamTimeout})
}

// relay copies bytes both ways until both sides are done.
func relay(client, upstream net.Conn) {
	var wg sync.WaitGroup
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		closeWrite(dst)
	}
	wg.Add(2)
	go pump(client, upstream)
	pump(upstream, client)
	wg.Wait()
}
