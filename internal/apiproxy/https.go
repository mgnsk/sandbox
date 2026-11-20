package apiproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/hostname"
	"github.com/mgnsk/sandbox/internal/mitmca"
	"github.com/mgnsk/sandbox/internal/popup"
)

// HTTPS serves a Proxy as an intercepting HTTPS_PROXY. The peer is pasta,
// so its popups can't name the requesting process.
type HTTPS struct {
	*Proxy
	ca       *mitmca.CA
	secret   string
	expected []byte
}

// Info is what the launcher needs to hand a client: the secret for
// Proxy-Authorization (user "sandbox") and the CA certificate to trust.
type Info struct {
	Secret string `json:"secret"`
	CA     string `json:"ca"`
}

// NewHTTPS makes an HTTPS proxy for p with a fresh CA and secret. With
// hosts (without ports), the CA signs for those only.
func NewHTTPS(p *Proxy, hosts ...string) (*HTTPS, error) {
	ca, err := mitmca.New("sandbox "+p.Name, hosts...)
	if err != nil {
		return nil, err
	}
	secret := rand.Text()
	return &HTTPS{
		Proxy:    p,
		ca:       ca,
		secret:   secret,
		expected: []byte("Basic " + base64.StdEncoding.EncodeToString([]byte("sandbox:"+secret))),
	}, nil
}

// RunHTTPS serves p as an intercepting HTTPS proxy on the launcher's
// listener until ctx ends, its CA signing for hosts only: a guard's Run,
// once it has its tokens.
func RunHTTPS(ctx context.Context, p *Proxy, hosts ...string) error {
	proxy, err := NewHTTPS(p, hosts...)
	if err != nil {
		return err
	}
	ln, err := guard.Listener()
	if err != nil {
		return err
	}
	if err := guard.Ready(proxy.Info()); err != nil {
		return err
	}
	return proxy.Serve(ctx, ln)
}

// Info is the proxy's secret and CA.
func (h *HTTPS) Info() Info {
	return Info{Secret: h.secret, CA: string(h.ca.PEM())}
}

// Serve answers CONNECTs on ln until ctx ends.
func (h *HTTPS) Serve(ctx context.Context, ln net.Listener) error {
	tunnels := newConnQueue(ln.Addr())
	inner := newServer(h.Proxy)
	inner.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connectKey{}, c.(*tunnelConn).target)
	}
	go func() { _ = inner.Serve(tunnels) }()
	defer inner.Close()
	return serve(ctx, newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.connect(w, r, tunnels)
	})), ln)
}

// connect answers a CONNECT: a tunnel to the real host, or one this proxy
// ends itself, reading the requests inside.
func (h *HTTPS) connect(w http.ResponseWriter, r *http.Request, tunnels *connQueue) {
	switch {
	case r.Method != http.MethodConnect:
		// Plain-HTTP proxying isn't offered: everything goes over CONNECT.
		h.refuse(w, http.StatusMethodNotAllowed, "only CONNECT")
		return
	case !h.authorized(r.Header.Values("Proxy-Authorization")):
		w.Header().Set("Proxy-Authenticate", `Basic realm="sandbox"`)
		h.refuse(w, http.StatusProxyAuthRequired, "proxy authentication required")
		return
	}
	target := strings.ToLower(r.Host)
	name, port, err := net.SplitHostPort(target)
	if err != nil || !hostname.ValidPort(target) {
		h.refuse(w, http.StatusBadRequest, "bad CONNECT target: "+popup.Clean(r.Host))
		return
	}
	host := target
	if port == "443" {
		host = name
	}

	var upstream net.Conn
	switch {
	case h.Tunnel != nil && h.Tunnel(target):
		if upstream, err = h.dial(r.Context(), target); err != nil {
			h.refuse(w, http.StatusBadGateway, "upstream error: "+err.Error())
			return
		}
	case h.Handles != nil && !h.Handles(host):
		h.refuse(w, StatusNotHandled, "not handled: "+popup.Clean(host))
		return
	}
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	client := bufferedConn(conn, buf.Reader)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		conn.Close()
		return
	}
	if upstream != nil {
		splice(client, upstream)
		return
	}
	cfg, err := h.ca.Config(name)
	if err != nil {
		conn.Close()
		return
	}
	tlsConn := tls.Server(client, cfg)
	_ = conn.SetDeadline(time.Now().Add(headerTimeout))
	if err := tlsConn.Handshake(); err != nil {
		conn.Close() // Client gone, or didn't trust the certificate.
		return
	}
	_ = conn.SetDeadline(time.Time{})
	tunnels.push(&tunnelConn{Conn: tlsConn, target: host})
}

// authorized says whether Proxy-Authorization (all its values) carries the
// secret.
func (h *HTTPS) authorized(values []string) bool {
	return len(values) == 1 &&
		subtle.ConstantTimeCompare([]byte(strings.TrimSpace(values[0])), h.expected) == 1
}

func (h *HTTPS) dial(ctx context.Context, addr string) (net.Conn, error) {
	if h.Dial != nil {
		return h.Dial(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// tunnelConn is a connection the proxy ends, read by the inner server.
type tunnelConn struct {
	net.Conn
	target string
}

// CloseWrite sends a close_notify: responses may be close-delimited, and
// rustls (fj) takes an EOF without one as a truncated body.
func (c *tunnelConn) CloseWrite() error { return closeWrite(c.Conn) }

// connQueue is a net.Listener for the tunnels the outer server hands over.
type connQueue struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnQueue(addr net.Addr) *connQueue {
	return &connQueue{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

func (q *connQueue) push(c net.Conn) {
	select {
	case q.conns <- c:
	case <-q.done:
		c.Close()
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *connQueue) Addr() net.Addr { return q.addr }

// bufferedConn reads what r already holds before conn.
func bufferedConn(conn net.Conn, r *bufio.Reader) net.Conn {
	if r.Buffered() == 0 {
		return conn
	}
	return &readerConn{Conn: conn, r: io.MultiReader(io.LimitReader(r, int64(r.Buffered())), conn)}
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *readerConn) CloseWrite() error { return closeWrite(c.Conn) }

// splice copies both ways until both sides are done, then closes both.
func splice(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = closeWrite(dst)
	}
	wg.Add(2)
	go pump(a, b)
	pump(b, a)
	wg.Wait()
}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
