// Package router is the HTTPS_PROXY every process inside the sandbox uses,
// so any gh or fj - the project's, home-manager's, ~/.nix-profile's - reaches
// the API guards without a wrapper of the sandbox's own.
//
// It runs inside, on the sandbox's own loopback, and answers CONNECTs:
//
//   - to the GitHub API hosts (ghproxy.TokenHosts), by chaining the CONNECT
//     to gh-api-proxy on the host;
//   - to any other host, first by asking forgejo-api-proxy, which takes the
//     hosts it holds a token for and answers apiproxy.StatusNotHandled for
//     the rest;
//   - otherwise by dialing the host itself, over the sandbox's own network,
//     exactly as a client without a proxy would.
//
// Nothing goes through the host that couldn't before: the guards still see
// only their own hosts, so they never become a way out to the host's
// services. Ports bound inside are forwarded to the host's loopback, so the
// router takes only CONNECTs carrying its own per-start secret, like the
// guards.
package router

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/ghproxy"
	"github.com/mgnsk/sandbox/internal/hostname"
)

// Each read of a client's or a guard's response head.
const headTimeout = 60 * time.Second

// Router answers CONNECTs; see the package comment.
type Router struct {
	// Secret is what clients send as Proxy-Authorization (user "sandbox").
	Secret string
	// GitHub and Forgejo are the guards' proxy URLs, secret included; nil
	// for a guard that's off.
	GitHub, Forgejo *url.URL
	// Dial reaches guards and hosts; a net.Dialer if nil.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Serve answers on ln until ctx ends.
func (r *Router) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           http.HandlerFunc(r.connect),
		ReadHeaderTimeout: headTimeout,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (r *Router) connect(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.Method != http.MethodConnect:
		refuse(w, http.StatusMethodNotAllowed, "only CONNECT (set HTTPS_PROXY, not HTTP_PROXY, to this)")
		return
	case !r.authorized(req.Header.Values("Proxy-Authorization")):
		w.Header().Set("Proxy-Authenticate", `Basic realm="sandbox"`)
		refuse(w, http.StatusProxyAuthRequired, "proxy authentication required")
		return
	}
	target := strings.ToLower(req.Host)
	name, port, err := net.SplitHostPort(target)
	if err != nil || !hostname.ValidPort(target) {
		refuse(w, http.StatusBadRequest, "bad CONNECT target")
		return
	}
	upstream, status, message := r.route(req.Context(), target, name, port)
	if upstream == nil {
		refuse(w, status, message)
		return
	}
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		conn.Close()
		upstream.Close()
		return
	}
	splice(withBuffered(conn, buf.Reader), upstream)
}

// route opens the way to target: through a guard or straight to it. On
// failure, the status and message to answer with.
func (r *Router) route(ctx context.Context, target, name, port string) (net.Conn, int, string) {
	if r.GitHub != nil && port == "443" && slices.Contains(ghproxy.TokenHosts, name) {
		conn, status, message := r.chain(ctx, r.GitHub, target)
		return conn, status, message
	}
	if r.Forgejo != nil {
		conn, status, message := r.chain(ctx, r.Forgejo, target)
		if status != apiproxy.StatusNotHandled {
			return conn, status, message
		}
	}
	conn, err := r.dial(ctx, target)
	if err != nil {
		return nil, http.StatusBadGateway, "dial " + target + ": " + err.Error()
	}
	return conn, 0, ""
}

// chain sends a CONNECT for target to the guard at proxy; the open tunnel,
// or the guard's status and message.
func (r *Router) chain(ctx context.Context, proxy *url.URL, target string) (net.Conn, int, string) {
	conn, err := r.dial(ctx, proxy.Host)
	if err != nil {
		return nil, http.StatusBadGateway, "guard unreachable: " + err.Error()
	}
	auth := ""
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		auth = "Proxy-Authorization: Basic " +
			base64.StdEncoding.EncodeToString([]byte(proxy.User.Username()+":"+password)) + "\r\n"
	}
	_ = conn.SetDeadline(time.Now().Add(headTimeout))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, auth); err != nil {
		conn.Close()
		return nil, http.StatusBadGateway, "guard: " + err.Error()
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, http.StatusBadGateway, "guard: " + err.Error()
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		conn.Close()
		return nil, resp.StatusCode, strings.TrimSpace(string(body))
	}
	_ = conn.SetDeadline(time.Time{})
	return withBuffered(conn, br), http.StatusOK, ""
}

func (r *Router) dial(ctx context.Context, addr string) (net.Conn, error) {
	if r.Dial != nil {
		return r.Dial(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// authorized says whether Proxy-Authorization (all its values) carries the
// secret.
func (r *Router) authorized(values []string) bool {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("sandbox:"+r.Secret))
	return len(values) == 1 && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(values[0])), []byte(want)) == 1
}

// refuse answers with message as the body, which curl and gh show.
func refuse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "sandbox router: "+message+"\n")
}

// withBuffered reads what r already holds before conn.
func withBuffered(conn net.Conn, r *bufio.Reader) net.Conn {
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
