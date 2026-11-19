// Package apiproxy is the proxy behind the sandbox's API guards
// (gh-api-proxy, forgejo-api-proxy, claude-api-proxy). Each guard runs on the
// host and holds the real token, which never enters the sandbox. Clients
// inside reach it one of two ways:
//
//   - ServeUnix: plain HTTP over a private unix socket the launcher binds
//     in, with the real host in Host (Claude Code's ANTHROPIC_UNIX_SOCKET).
//   - ServeHTTPS: an HTTPS_PROXY on the host's loopback, which pasta maps
//     into the sandbox. A client CONNECTs (with the per-launch secret in
//     Proxy-Authorization), the proxy answers the TLS handshake itself with
//     a certificate from its own throwaway CA (mitmca), which only the
//     sandbox's gh and fj wrappers trust, and reads the request inside.
//
// Either way, per request, the proxy:
//
//   - refuses malformed requests, and hosts and paths the guard doesn't
//     allow;
//   - forwards reads as-is, and holds writes for the user's approval in a
//     popup (the guard decides what counts as a write);
//   - drops the client's Authorization (and any other credential header the
//     guard names) and adds the guard's own, then relays the request to the
//     real host over HTTPS.
//
// A guard is a Policy.
package apiproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mgnsk/sandbox/internal/popup"
)

const (
	requestTimeout  = 60 * time.Second  // Each read/write of the client.
	upstreamTimeout = 300 * time.Second // Each read/write of upstream.
)

// Hop-by-hop headers (RFC 9110 7.6.1) plus the ones this proxy sets
// itself. Expect is answered here.
var dropRequestHeaders = []string{
	"host", "authorization", "connection", "keep-alive", "proxy-authorization",
	"proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "expect",
}

var dropResponseHeaders = []string{
	"connection", "keep-alive", "proxy-authenticate", "proxy-connection",
	"trailer", "transfer-encoding", "upgrade",
}

// Policy is what a guard decides. Hosts and paths are as the client sent
// them, read as Latin-1; hosts lowercased, without ":443".
type Policy interface {
	// Name names the guard in refusals and popups.
	Name() string
	// PopupTitle heads the approval popup.
	PopupTitle() string
	// HostAllowed says whether requests to host are forwarded at all.
	HostAllowed(host string) bool
	// HostRefusal is the message refusing a host that isn't allowed.
	HostRefusal(host string) string
	// TunnelAllowed says whether a CONNECT to host ("name" or "name:port")
	// is passed through as it is, unread: hosts that get no credentials,
	// which the client's children (git under gh) may reach too.
	TunnelAllowed(host string) bool
	// PathAllowed says whether requests for path (with its query) on host
	// are forwarded.
	PathAllowed(host, path string) bool
	// UpstreamHost is the host to forward an allowed request for host to.
	UpstreamHost(host string) string
	// BodyLimit says to read the request body in full, up to limit bytes,
	// and hand it to DescribeWrite, rather than stream it.
	BodyLimit(host, path string) (limit int64, ok bool)
	// DescribeWrite describes a write for the approval popup, or says the
	// request only reads (ok=false).
	DescribeWrite(method, host, path string, body []byte) (description string, ok bool)
	// CredentialHeaders are client headers (lower case) dropped besides
	// Authorization: ones that carry credentials the guard replaces.
	CredentialHeaders() []string
	// Credentials are the headers to send to host.
	Credentials(host string) []Header
}

// Header is a header a guard sends upstream.
type Header struct{ Name, Value string }

// Defaults is a Policy's usual answers, for a guard to embed.
type Defaults struct{}

func (Defaults) PopupTitle() string                     { return "Allow sandboxed API write?" }
func (Defaults) HostRefusal(host string) string         { return "host not allowed: " + host }
func (Defaults) TunnelAllowed(string) bool              { return false }
func (Defaults) PathAllowed(string, string) bool        { return true }
func (Defaults) UpstreamHost(host string) string        { return host }
func (Defaults) BodyLimit(string, string) (int64, bool) { return 0, false }
func (Defaults) CredentialHeaders() []string            { return nil }
func (Defaults) DescribeWrite(method, host, path string, _ []byte) (string, bool) {
	if method == "GET" || method == "HEAD" {
		return "", false
	}
	return method + " " + host + path, true
}

// TestUpstreamEnv names where the tests' stand-in for every real host
// listens (host:port): upstream connections go there instead, with TLS
// still verified for the real host's name against SSL_CERT_FILE, which
// they point at their own CA. From the guard's environment - the host
// launcher's, never the sandbox's.
const TestUpstreamEnv = "SANDBOX_TEST_UPSTREAM"

// upstreamAddress is the address to connect to for the real host
// name:port.
func upstreamAddress(name, port string) string {
	if override := os.Getenv(TestUpstreamEnv); override != "" {
		return override
	}
	return net.JoinHostPort(name, port)
}

func splitHost(host string) (name, port string) {
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		return host[:i], host[i+1:]
	}
	return host, "443"
}

// dialUpstream opens a TLS connection to the real host ("name" or
// "name:port").
func dialUpstream(host string) (net.Conn, error) {
	name, port := splitHost(host)
	dialer := &net.Dialer{Timeout: upstreamTimeout}
	raw, err := dialer.Dial("tcp", upstreamAddress(name, port))
	if err != nil {
		return nil, err
	}
	conn := tls.Client(&timeoutConn{raw, upstreamTimeout}, &tls.Config{ServerName: name})
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// server runs a Policy over either transport.
type server struct {
	policy    Policy
	approvals popup.Approvals
}

func (s *server) refuse(w io.Writer, status int, message string, extra ...header) {
	refuse(w, s.policy.Name(), status, message, extra...)
}

// approve says whether to let a write through, per the popup or an earlier
// "always" answer. The popup can't name the requesting process: behind
// pasta there's no knowing it, and the guard on a unix socket (Claude's)
// never asks.
func (s *server) approve(description string) bool {
	return s.approvals.Approve(func() string {
		text := s.policy.PopupTitle() + "\n\n" + clean(description) + "\n"
		return popup.Ask(s.policy.Name(), text)
	})
}

// readOne reads a request off br, answering Expect: 100-continue; nil if
// there's none to handle (refused, or the client sent nothing).
func (s *server) readOne(br *bufio.Reader, w io.Writer) *request {
	r, herr := readRequest(br)
	if herr != nil {
		s.refuse(w, herr.status, herr.message)
		return nil
	}
	if r == nil {
		return nil
	}
	if expect := r.all("expect"); len(expect) > 0 && asciiLower(expect[0]) == "100-continue" &&
		r.version >= "HTTP/1.1" {
		if _, err := io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return nil
		}
	}
	return r
}

func isProxied(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	}
	return false
}

// handle answers one request on conn: validate, classify, approve,
// forward. tunnelHost is the CONNECT target ("host" or "host:port") for a
// request read inside a tunnel, which its Host must name; "" for none.
func (s *server) handle(conn net.Conn, br *bufio.Reader, tunnelHost string) {
	r := s.readOne(br, conn)
	if r == nil {
		return
	}
	if !isProxied(r.method) {
		s.refuse(conn, http.StatusNotImplemented, "unsupported method ("+clean(latin1(r.method))+")")
		return
	}
	host, length, ok := s.check(conn, r, tunnelHost)
	if !ok {
		return
	}
	path := latin1(r.path)

	var body []byte
	if limit, ok := s.policy.BodyLimit(host, path); ok {
		if length > limit {
			s.refuse(conn, http.StatusRequestEntityTooLarge, "request body too large to classify")
			return
		}
		body = make([]byte, length)
		if _, err := io.ReadFull(br, body); err != nil {
			return
		}
	}

	if description, ok := s.policy.DescribeWrite(r.method, host, path, body); ok &&
		!s.approve(description) {
		s.refuse(conn, http.StatusForbidden, "declined by user")
		return
	}
	s.forward(conn, br, r, host, length, body)
}

// check returns the host and body length of a well-formed request to an
// allowed host, else refuses it. One Host and at most one Content-Length:
// this proxy and upstream must agree on both.
func (s *server) check(w io.Writer, r *request, tunnelHost string) (string, int64, bool) {
	hosts := r.all("host")
	lengths := r.all("content-length")
	if lengths == nil {
		lengths = []string{"0"}
	}
	host := ""
	if len(hosts) == 1 {
		host = strings.TrimSuffix(asciiLower(latin1(hosts[0])), ":443")
	}
	path := latin1(r.path)
	switch {
	case !strings.HasPrefix(r.path, "/"):
		s.refuse(w, http.StatusBadRequest, "expected an origin-form request target")
	case tunnelHost != "" && host != tunnelHost:
		s.refuse(w, http.StatusMisdirectedRequest, "Host "+clean(host)+" isn't the CONNECT target")
	case !s.policy.HostAllowed(host):
		s.refuse(w, http.StatusForbidden, s.policy.HostRefusal(clean(host)))
	case !s.policy.PathAllowed(host, path):
		s.refuse(w, http.StatusForbidden, "path not allowed: "+clean(path))
	case r.has("transfer-encoding"):
		s.refuse(w, http.StatusLengthRequired, "chunked request bodies are not supported")
	default:
		n, err := strconv.ParseInt(lengths[0], 10, 64)
		if len(lengths) != 1 || !isDigits(lengths[0]) || err != nil {
			s.refuse(w, http.StatusBadRequest, "bad Content-Length")
			break
		}
		return host, n, true
	}
	return "", 0, false
}

// validPath is what may go upstream as a request target: printable ASCII.
func validPath(path string) bool {
	for i := 0; i < len(path); i++ {
		if c := path[i]; c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

func validValue(value string) bool {
	return !strings.ContainsAny(value, "\r\n\x00")
}

// forward sends the request upstream and streams the response back.
func (s *server) forward(conn net.Conn, br *bufio.Reader, r *request, host string, length int64, body []byte) {
	host = s.policy.UpstreamHost(host)
	upstream, err := s.sendUpstream(br, r, host, length, body)
	if upstream != nil {
		defer upstream.Close()
	}
	var resp *http.Response
	var ubr *bufio.Reader
	if err == nil {
		ubr = bufio.NewReaderSize(upstream, chunk)
		for {
			resp, err = http.ReadResponse(ubr, &http.Request{Method: r.method})
			if err != nil || resp.StatusCode != http.StatusContinue {
				break
			}
		}
	}
	if err != nil {
		s.refuse(conn, http.StatusBadGateway, fmt.Sprintf("upstream error: %v", err))
		return
	}
	defer resp.Body.Close()
	relayResponse(conn, resp, r.method)
}

// sendUpstream writes the request line, the client's headers minus the
// dropped ones, the guard's credentials, then the body - already read, or
// streamed from the client.
func (s *server) sendUpstream(br *bufio.Reader, r *request, host string, length int64, body []byte) (net.Conn, error) {
	if !validPath(r.path) {
		return nil, errors.New("URL can't contain control characters or non-ASCII")
	}
	drop := append(slices.Clone(dropRequestHeaders), s.policy.CredentialHeaders()...)
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.method, r.path, host)
	for _, h := range r.headers {
		if !slices.Contains(drop, asciiLower(h.name)) {
			fmt.Fprintf(&b, "%s: %s\r\n", h.name, h.value)
		}
	}
	for _, h := range s.policy.Credentials(host) {
		if !validValue(h.Value) {
			return nil, errors.New("malformed credential")
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
	}
	b.WriteString("\r\n")

	upstream, err := dialUpstream(host)
	if err != nil {
		return nil, err
	}
	if _, err := upstream.Write(b.Bytes()); err != nil {
		return upstream, err
	}
	if body != nil {
		_, err := upstream.Write(body)
		return upstream, err
	}
	buf := make([]byte, chunk)
	for remaining := length; remaining > 0; {
		n, err := br.Read(buf[:min(int64(len(buf)), remaining)])
		if n > 0 {
			if _, werr := upstream.Write(buf[:n]); werr != nil {
				return upstream, werr
			}
			remaining -= int64(n)
		}
		if err != nil {
			if remaining > 0 {
				return upstream, errors.New("client closed the connection mid-body")
			}
			break
		}
	}
	return upstream, nil
}

// relayResponse writes upstream's status, headers minus the dropped ones,
// and body - close-delimited, so whatever its framing upstream.
func relayResponse(w io.Writer, resp *http.Response, method string) {
	var b bytes.Buffer
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, reason)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range resp.Header {
			if !yield(k) {
				return
			}
		}
	}) {
		if slices.Contains(dropResponseHeaders, asciiLower(name)) {
			continue
		}
		for _, v := range resp.Header[name] {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := w.Write(b.Bytes()); err != nil || method == "HEAD" {
		return
	}
	// Each read written at once, so event streams aren't held back.
	buf := make([]byte, chunk)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ServeUnix runs policy as a guard on the unix socket at path, taking plain
// HTTP, until the listener fails.
func ServeUnix(path string, policy Policy) error {
	if _, err := os.Lstat(path); err == nil {
		_ = os.Remove(path)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	s := &server{policy: policy}
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go func() {
			c := &timeoutConn{conn, requestTimeout}
			defer conn.Close()
			s.handle(c, bufio.NewReader(c), "")
			_ = conn.CloseWrite()
		}()
	}
}
