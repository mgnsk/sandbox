// Package openurl is open-url-guard: it opens web URLs from a sandbox in the
// host's browser, behind a popup.
//
//	sandbox-bin open-url-guard
//
// The sandbox has no display, so its xdg-open (sandbox-bin xdg-open) sends the
// URL here instead. The host's xdg-open picks a handler by scheme, and for a
// path by file type, so it only ever gets a URL that passed Validate:
// anything else could start an arbitrary host application on sandbox-chosen
// input.
//
// Protocol: the client sends one line, the URL, and gets back one line, "ok"
// or "denied: <reason>".
package openurl

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/peer"
	"github.com/mgnsk/sandbox/internal/popup"
)

const (
	maxURLSize = 4096
	// How long a client has to send its URL.
	readTimeout = 10 * time.Second
	// How much of the requester's own words a popup shows.
	displayLimit = 200
)

// Validate says why rawURL must not be opened, or returns nil if it may be
// offered to the user.
//
// The checks on the raw text come first: a URL parser may silently drop tabs
// and newlines, so it would judge a different URL from the one handed on.
func Validate(rawURL string) error {
	if strings.ContainsFunc(rawURL, func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r)
	}) {
		// Also what rules out a homograph host: the popup shows the host as
		// its punycode or not at all.
		return errors.New("not printable ASCII")
	}
	if strings.Contains(rawURL, `\`) {
		// Browsers read it as "/", URL parsers don't: the host shown for
		// https://github.com\.evil.example wouldn't be the one loaded.
		return errors.New("backslash in URL")
	}
	u, err := url.Parse(rawURL)
	switch {
	case err != nil:
		return errors.New("malformed URL")
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("only http and https URLs can be opened")
	case u.Opaque != "", u.Hostname() == "":
		return errors.New("no host")
	case !validHost(u):
		return errors.New("malformed host")
	case u.User != nil:
		// https://github.com@evil.example reads as github.com in a popup.
		return errors.New("user info in URL")
	}
	return nil
}

// validHost says whether u's host reads the same to a browser: brackets
// only around an IPv6 address, and nothing percent-encoded - the parser
// decodes g%D1%96thub.com to a name with a Cyrillic letter, which the popup
// would show as it looks, where a browser loads its punycode.
func validHost(u *url.URL) bool {
	if strings.ContainsFunc(u.Host, func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r)
	}) {
		return false
	}
	if !strings.HasPrefix(u.Host, "[") {
		// The % of an escape the parser left alone.
		return !strings.ContainsAny(u.Host, "[]%")
	}
	addr, err := netip.ParseAddr(u.Hostname())
	return err == nil && addr.Is6()
}

// Guard opens URLs its clients send, once the user approves.
type Guard struct {
	// Open hands a URL to the host; xdg-open in its own session if nil.
	Open func(rawURL string) error
	// Ask asks the user; popup.Ask if nil.
	Ask func(name, text string) popup.Answer

	approvals popup.Approvals
}

// Handle answers one client's request to open a URL.
func (g *Guard) Handle(conn net.Conn) {
	defer conn.Close()
	who := peer.Describe(conn)
	reply := "ok"
	if err := g.handle(conn, who); err != nil {
		reply = "denied: " + err.Error()
	}
	_, _ = io.WriteString(conn, reply+"\n")
}

func (g *Guard) handle(conn net.Conn, who peer.Peer) error {
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	rawURL, err := readLine(conn)
	if err != nil {
		return err
	}
	if err := Validate(rawURL); err != nil {
		return err
	}
	if !g.approvals.Approve(func() popup.Answer { return g.confirm(rawURL, who) }) {
		return errors.New("not approved")
	}
	open := g.Open
	if open == nil {
		open = xdgOpen
	}
	if err := open(rawURL); err != nil {
		return fmt.Errorf("couldn't run xdg-open: %w", err)
	}
	return nil
}

// readLine reads the client's first line.
func readLine(conn net.Conn) (string, error) {
	errBad := errors.New("URL too long or not UTF-8")
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxURLSize+1), maxURLSize+1).ReadString('\n')
	line = strings.TrimSuffix(line, "\n")
	if err != nil && !errors.Is(err, io.EOF) || len(line) > maxURLSize || !utf8.ValidString(line) {
		return "", errBad
	}
	return line, nil
}

// confirm asks in a popup whether to open rawURL. Shown whole and wrapped,
// not truncated: a URL is approved for exactly what's on screen.
func (g *Guard) confirm(rawURL string, who peer.Peer) popup.Answer {
	u, _ := url.Parse(rawURL)
	ask := g.Ask
	if ask == nil {
		ask = func(name, text string) popup.Answer { return popup.AskFrom(name, text, who.Session) }
	}
	return ask("open-url-guard", "Open in the host's browser?\n\n"+
		"  host:     "+popup.Clean(u.Hostname())+"\n"+
		"  cwd:      "+popup.CleanLimit(who.Cwd, displayLimit)+"\n"+
		"  command:  "+popup.CleanLimit(who.Cmdline, displayLimit)+"\n\n"+
		rawURL+"\n\n")
}

// xdgOpen hands a validated URL to the host's xdg-open, from PATH (which the
// launcher starts with the store's xdg-utils). In its own session, since a
// browser it starts has to outlive this guard and the sandbox.
func xdgOpen(rawURL string) error {
	cmd := exec.Command("xdg-open", rawURL)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() //nolint:errcheck // Reaped only.
	return nil
}

// Run serves on the launcher's socket until stopped.
func Run(ctx context.Context) error {
	ln, err := guard.Listener()
	if err != nil {
		return err
	}
	if err := guard.Ready(struct{}{}); err != nil {
		return err
	}
	return guard.Serve(ctx, ln, (&Guard{}).Handle)
}
