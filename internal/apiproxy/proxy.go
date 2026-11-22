// Package apiproxy is the proxy behind the sandbox's API guards
// (gh-api-proxy, forgejo-api-proxy, claude-api-proxy). Each guard runs on the
// host and holds the real token, which never enters the sandbox. Clients
// inside reach it one of two ways:
//
//   - Serve: plain HTTP over a private unix socket the launcher binds in,
//     with the real host in Host (Claude Code's ANTHROPIC_UNIX_SOCKET).
//   - HTTPS.Serve: an HTTPS_PROXY on the host's loopback, which pasta maps
//     into the sandbox. A client CONNECTs (with the per-launch secret in
//     Proxy-Authorization), the proxy answers the TLS handshake itself with
//     a certificate from its own throwaway CA (mitmca), which clients inside
//     trust, and reads the requests inside. Inside, clients reach it
//     through the sandbox's router (internal/router).
//
// Either way, per request, the proxy:
//
//   - refuses hosts and paths the guard doesn't allow;
//   - forwards reads as they are, and holds writes for the user's approval
//     in a popup (the guard decides what counts as a write);
//   - drops the client's Authorization (and any other credential header the
//     guard names) and adds the guard's own, then relays the request to the
//     real host over HTTPS.
package apiproxy

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mgnsk/sandbox/internal/popup"
)

const (
	// Each read of a client's request head.
	headerTimeout = 60 * time.Second
	// How long a connection may sit between requests.
	idleTimeout = 2 * time.Minute
	// The largest request body read to show it in a popup; a larger one
	// is described, not shown.
	maxShownBody = 256 << 10
	// How much of a body a popup shows: it has to fit the launcher's
	// limit on a request, with room to spare.
	maxShown = 32 << 10
)

// Headers that have a server treat a request as another method than the
// one this proxy judged it by; never forwarded.
var methodOverrides = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}

// StatusNotHandled answers a CONNECT to a host the guard doesn't take (see
// Guard.Handles).
const StatusNotHandled = http.StatusNotFound

// Guard is what an API guard decides; the proxy does the rest.
type Guard struct {
	// Name names the guard in refusals and popups.
	Name string
	// Title heads the approval popup.
	Title string
	// Route says where a request for host (lowercase, without ":443") goes,
	// or refuses it with the error's message.
	Route func(host string) (Route, error)
	// AllowPath, if set, refuses requests whose path it returns false for.
	AllowPath func(path string) bool
	// Describe describes a write for the approval popup, or returns "" for a
	// read; it may read the body with ReadBody. Unset, everything but GET
	// and HEAD is a write, described by DescribeWrite.
	Describe func(r *http.Request, host string) (string, error)
	// Handles, if set, says which hosts (lowercase, without ":443") this
	// guard takes at all. A CONNECT to any other is answered
	// StatusNotHandled before anything is read, so the sandbox's router
	// sends it straight to the host instead. Checked per CONNECT.
	Handles func(host string) bool
	// Tunnel, if set, says which CONNECT targets (host:port) are passed
	// through as they are, unread: hosts that get no credentials, which the
	// client's children (git under gh) may reach too.
	Tunnel func(hostport string) bool
	// DropHeaders are client headers dropped besides Authorization: ones
	// carrying credentials the guard replaces.
	DropHeaders []string
}

// Route is where a request goes: the real host, and the headers that
// authenticate it there.
type Route struct {
	Host   string
	Header http.Header
}

// TokenRoute is the route to host with token as its credential, the way
// GitHub's and Forgejo's APIs take one.
func TokenRoute(host, token string) Route {
	return Route{Host: host, Header: http.Header{"Authorization": {"token " + token}}}
}

// Proxy runs a Guard.
type Proxy struct {
	Guard
	// Transport reaches the real hosts; a plain HTTPS client if nil.
	Transport http.RoundTripper
	// Dial reaches tunneled hosts; a net.Dialer if nil.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Ask asks the user to approve a write; popup.Ask if nil.
	Ask func(popup.Request) popup.Answer

	approvals popup.Approvals
	once      sync.Once
	forwarder *httputil.ReverseProxy
}

type routeKey struct{}

// connectKey holds the CONNECT target of a request read inside a tunnel,
// which its Host must name.
type connectKey struct{}

// ServeHTTP answers one request read off a client: check, classify,
// approve, forward.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		p.refuse(w, http.StatusNotImplemented, "unsupported method ("+popup.Clean(r.Method)+")")
		return
	}
	if !strings.HasPrefix(r.RequestURI, "/") {
		p.refuse(w, http.StatusBadRequest, "expected an origin-form request target")
		return
	}
	// A connection that leaves HTTP, with the guard's credentials on it
	// and nothing read of what follows.
	if r.Header.Get("Upgrade") != "" {
		p.refuse(w, http.StatusNotImplemented, "protocol upgrades aren't forwarded")
		return
	}
	host := strings.TrimSuffix(strings.ToLower(r.Host), ":443")
	if target, ok := r.Context().Value(connectKey{}).(string); ok && host != target {
		p.refuse(w, http.StatusMisdirectedRequest, "Host "+popup.Clean(host)+" isn't the CONNECT target")
		return
	}
	route, err := p.Route(host)
	if err != nil {
		p.refuse(w, http.StatusForbidden, err.Error())
		return
	}
	if p.AllowPath != nil && !p.AllowPath(r.URL.Path) {
		p.refuse(w, http.StatusForbidden, "path not allowed: "+popup.Clean(r.URL.RequestURI()))
		return
	}
	description, err := p.describe(r, host)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		p.refuse(w, http.StatusRequestEntityTooLarge, "request body too large to classify")
		return
	case err != nil:
		p.refuse(w, http.StatusBadRequest, err.Error())
		return
	case description != "" && !p.approve(description):
		p.refuse(w, http.StatusForbidden, "declined by user")
		return
	}
	p.once.Do(p.init)
	p.forwarder.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), routeKey{}, route)))
}

func (p *Proxy) describe(r *http.Request, host string) (string, error) {
	if p.Describe != nil {
		return p.Describe(r, host)
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return "", nil
	}
	return DescribeWrite(r, host)
}

// DescribeWrite describes a write for the approval popup: its target, then
// its body - a path alone doesn't say whether a PATCH renames a repository
// or makes it public. A JSON body of a known, moderate size is shown; any
// other is said to be there, with its size and type.
func DescribeWrite(r *http.Request, host string) (string, error) {
	target := Target(r, host)
	kind, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch {
	case r.ContentLength == 0:
		return target, nil
	case r.ContentLength < 0:
		return target + "\n\n(a body of unknown size, not shown)", nil
	case r.ContentLength > maxShownBody || kind != "" && kind != "application/json" && !strings.HasSuffix(kind, "+json"):
		return fmt.Sprintf("%s\n\n(a body of %d bytes, %s, not shown)", target, r.ContentLength, orUnknown(kind)), nil
	}
	body, err := ReadBody(r, maxShownBody)
	if err != nil {
		return "", err
	}
	// Of no stated type, only what turns out to be JSON.
	if kind == "" && !jsontext.Value(body).IsValid() {
		return fmt.Sprintf("%s\n\n(a body of %d bytes, %s, not shown)", target, len(body), orUnknown(kind)), nil
	}
	return target + "\n\n" + Shown(string(indented(body))), nil
}

func orUnknown(kind string) string {
	if kind == "" {
		return "of unknown type"
	}
	return kind
}

// indented is JSON data indented, or data as it is if it isn't JSON.
func indented(data []byte) []byte {
	v := jsontext.Value(bytes.Clone(data))
	if v.Indent(jsontext.WithIndent("  ")) != nil {
		return data
	}
	return v
}

// Shown is text as a popup shows it: cut to maxShown bytes, saying how
// much is left out.
func Shown(text string) string {
	if len(text) <= maxShown {
		return text
	}
	return fmt.Sprintf("%s\n... (%d more bytes, not shown)", strings.ToValidUTF8(text[:maxShown], ""), len(text)-maxShown)
}

// Target is a request's method, host and path, as a popup shows it.
func Target(r *http.Request, host string) string {
	return r.Method + " " + host + r.URL.RequestURI()
}

// approve says whether to let a write through, per the popup or an earlier
// "always" answer. The popup can't name the requesting process: behind
// pasta there's no knowing it.
func (p *Proxy) approve(description string) bool {
	ask := p.Ask
	if ask == nil {
		ask = popup.Ask
	}
	return p.approvals.Approve(func() popup.Answer {
		return ask(popup.Request{Name: p.Name, Text: p.Title + "\n\n" + popup.CleanText(description) + "\n"})
	})
}

func (p *Proxy) init() {
	transport := p.Transport
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		// Never the host's HTTPS_PROXY: straight to the real host.
		t.Proxy = nil
		transport = t
	}
	p.forwarder = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			route := pr.In.Context().Value(routeKey{}).(Route)
			pr.SetURL(&url.URL{Scheme: "https", Host: route.Host})
			// The client's credentials are placeholders, never forwarded;
			// Expect is answered here.
			for _, name := range slices.Concat([]string{"Authorization", "Expect"}, methodOverrides, p.DropHeaders) {
				pr.Out.Header.Del(name)
			}
			maps.Copy(pr.Out.Header, route.Header)
		},
		Transport: transport,
		// Each read written at once, so event streams aren't held back.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			p.refuse(w, http.StatusBadGateway, "upstream error: "+err.Error())
		},
	}
}

// refuse answers with an error gh and fj show as its message.
func (p *Proxy) refuse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"message": p.Name + ": " + message})
}

// Serve answers plain HTTP on ln until ctx ends.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	return serve(ctx, newServer(p), ln)
}

// newServer is a server for h. Its own log stays quiet: a guard's stderr is
// the terminal the sandbox runs on.
func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

func serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ReadBody reads r's body in full, up to limit bytes, leaving it in place to
// be forwarded; an *http.MaxBytesError past limit.
//
// With GetBody too, so the transport can send it again: an HTTP/2
// connection the host shuts down (GOAWAY) after the body went out is
// retried on a new one only with it, and is a 502 without.
func ReadBody(r *http.Request, limit int64) ([]byte, error) {
	if r.ContentLength > limit {
		return nil, &http.MaxBytesError{Limit: limit}
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, limit))
	if err != nil {
		return nil, err
	}
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	r.Body, _ = r.GetBody()
	r.ContentLength = int64(len(body))
	return body, nil
}
