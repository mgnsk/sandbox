// Package openurl is open-url-guard: it opens web URLs from a sandbox in the
// host's browser, behind a popup.
//
//	open-url-guard SOCKET
//
// The sandbox has no display, so its xdg-open (sandbox-xdg-open) sends the
// URL here instead. The host's xdg-open picks a handler by scheme, and for a
// path by file type, so it only ever gets a URL that passed Validate:
// anything else could start an arbitrary host application on sandbox-chosen
// input.
//
// Protocol: the client sends one line, the URL, and gets back one line, "ok"
// or "denied: <reason>".
package openurl

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/mgnsk/sandbox/internal/cover"
	"github.com/mgnsk/sandbox/internal/peer"
	"github.com/mgnsk/sandbox/internal/popup"
)

// From PATH, which the launcher starts with the store's xdg-utils.
const xdgOpen = "xdg-open"

const maxURLSize = 4096

var approvals popup.Approvals

// url is a URL split as Python's urllib.parse.urlsplit does, as far as
// Validate looks: the guard has to judge the URL the way the browser will
// read it, and these rules are the ones it was written against.
type url struct {
	scheme, netloc string
}

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '+' || c == '-' || c == '.'
}

var ipvFuture = regexp.MustCompile(`\Av[a-fA-F0-9]+\..+\z`)

func split(s string) (url, error) {
	var u url
	if i := strings.IndexByte(s, ':'); i > 0 && (s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		ok := true
		for j := range i {
			if !isSchemeChar(s[j]) {
				ok = false
				break
			}
		}
		if ok {
			u.scheme, s = strings.ToLower(s[:i]), s[i+1:]
		}
	}
	if rest, ok := strings.CutPrefix(s, "//"); ok {
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		u.netloc = rest[:end]
		open, close := strings.Contains(u.netloc, "["), strings.Contains(u.netloc, "]")
		if open != close {
			return u, errors.New("invalid IPv6 URL")
		}
		if open {
			hostport := u.netloc[strings.LastIndexByte(u.netloc, '@')+1:]
			before, after, found := strings.Cut(hostport, "[")
			host, port, _ := strings.Cut(after, "]")
			switch {
			case !found:
			case before != "", port != "" && !strings.HasPrefix(port, ":"):
				return u, errors.New("invalid IPv6 URL")
			case strings.HasPrefix(host, "v"):
				if !ipvFuture.MatchString(host) {
					return u, errors.New("invalid IPvFuture host")
				}
			default:
				if addr, err := netip.ParseAddr(host); err != nil || !addr.Is6() {
					return u, errors.New("invalid IPv6 host")
				}
			}
		}
	}
	return u, nil
}

// hostname is the host of the URL's netloc, lowercased.
func (u url) hostname() string {
	hostport := u.netloc
	if i := strings.LastIndexByte(hostport, '@'); i >= 0 {
		hostport = hostport[i+1:]
	}
	var host string
	if strings.Contains(hostport, "[") {
		_, after, _ := strings.Cut(hostport, "[")
		host, _, _ = strings.Cut(after, "]")
	} else {
		host, _, _ = strings.Cut(hostport, ":")
	}
	return strings.ToLower(host)
}

// Validate says why rawURL must not be opened, or "" if it may be offered to
// the user.
//
// The checks on the raw text come first: a URL parser may silently drop tabs
// and newlines, so it would judge a different URL from the one handed on.
func Validate(rawURL string) string {
	for i := 0; i < len(rawURL); i++ {
		if c := rawURL[i]; c <= ' ' || c >= 0x7f {
			// Also what rules out a homograph host: the popup shows the
			// host as its punycode or not at all.
			return "not printable ASCII"
		}
	}
	if strings.Contains(rawURL, `\`) {
		// Browsers read it as "/", URL parsers don't: the host shown for
		// https://github.com\.evil.example wouldn't be the one loaded.
		return "backslash in URL"
	}
	u, err := split(rawURL)
	if err != nil {
		return "malformed URL"
	}
	if u.scheme != "http" && u.scheme != "https" {
		return "only http and https URLs can be opened"
	}
	if u.hostname() == "" {
		return "no host"
	}
	if strings.Contains(u.netloc, "@") {
		// https://github.com@evil.example reads as github.com in a popup.
		return "user info in URL"
	}
	return ""
}

// confirm asks in a popup whether to open rawURL. Shown whole and wrapped,
// not truncated: a URL is approved for exactly what's on screen.
func confirm(rawURL, cwd, cmdline string) string {
	u, _ := split(rawURL)
	text := "Open in the host's browser?\n\n" +
		"  host:     " + popup.Clean(u.hostname()) + "\n" +
		"  cwd:      " + popup.Clean(cwd) + "\n" +
		"  command:  " + popup.Clean(cmdline) + "\n\n" +
		rawURL + "\n\n"
	return popup.Ask("open-url-guard", text)
}

// open hands a validated URL to the host's xdg-open. In its own session,
// since a browser it starts has to outlive this guard and the sandbox.
func open(rawURL string) error {
	cmd := exec.Command(xdgOpen, rawURL)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() //nolint:errcheck // reaped only
	return nil
}

// strerror words err as the C library would ("No such file or directory").
func strerror(err error) string {
	var errno syscall.Errno
	switch {
	case errors.Is(err, exec.ErrNotFound):
		errno = syscall.ENOENT
	case !errors.As(err, &errno):
		return err.Error()
	}
	s := errno.Error()
	return strings.ToUpper(s[:1]) + s[1:]
}

// readLine reads the first line from conn, or ok=false if it's too long or
// isn't UTF-8.
func readLine(conn net.Conn) (line string, ok bool) {
	var buf []byte
	chunk := make([]byte, maxURLSize+1)
	for !bytes.Contains(buf, []byte("\n")) {
		if len(buf) > maxURLSize {
			return "", false
		}
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			break
		}
	}
	first, _, _ := bytes.Cut(buf, []byte("\n"))
	if len(first) > maxURLSize || !utf8.Valid(first) {
		return "", false
	}
	return string(first), true
}

// handle answers one client's request to open a URL.
func handle(conn *net.UnixConn) {
	defer conn.Close()
	cwd, cmdline := peer.Describe(conn)
	rawURL, ok := readLine(conn)
	reason := "URL too long or not UTF-8"
	if ok {
		reason = Validate(rawURL)
	}
	if reason == "" && !approvals.Approve(func() string { return confirm(rawURL, cwd, cmdline) }) {
		reason = "not approved"
	}
	if reason == "" {
		if err := open(rawURL); err != nil {
			reason = fmt.Sprintf("couldn't run %s: %s", xdgOpen, strerror(err))
		}
	}
	reply := "ok\n"
	if reason != "" {
		reply = "denied: " + reason + "\n"
	}
	_, _ = conn.Write([]byte(reply))
}

// Main listens on argv[1].
func Main(argv []string) int {
	if len(argv) != 2 {
		fmt.Fprintln(os.Stderr, "usage: open-url-guard SOCKET")
		return 2
	}
	cover.DieOnSignals()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: argv[1], Net: "unix"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open-url-guard: %v\n", err)
		return 1
	}
	// Left in place when the guard ends, as the launcher removes its dir.
	ln.SetUnlinkOnClose(false)
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			fmt.Fprintf(os.Stderr, "open-url-guard: %v\n", err)
			return 1
		}
		go handle(conn)
	}
}
