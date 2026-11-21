package sshagent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mgnsk/sandbox/internal/popup"
)

// The extension OpenSSH's ssh (8.9 and later) sends before a login, binding
// the agent connection to the server's host key (PROTOCOL.agent).
const sessionBind = "session-bind@openssh.com"

// OpenSSH's agent keeps as many binds per connection.
const maxBinds = 16

var errBadBind = errors.New("bad session-bind")

// bind is a session the client bound: the server holding host signed the
// session's identifier, the exchange hash of a key exchange the client took
// part in. A login signature names its session, so it only logs in to that
// server.
type bind struct {
	session    []byte
	host       ssh.PublicKey
	forwarding bool
}

// parseBind reads and verifies a session-bind's contents.
func parseBind(contents []byte) (bind, error) {
	var msg struct {
		HostKey, Session, Signature []byte
		Forwarding                  bool
	}
	if ssh.Unmarshal(contents, &msg) != nil || len(msg.Session) == 0 {
		return bind{}, errBadBind
	}
	host, err := ssh.ParsePublicKey(msg.HostKey)
	if err != nil {
		return bind{}, errBadBind
	}
	var sig ssh.Signature
	if ssh.Unmarshal(msg.Signature, &sig) != nil || host.Verify(msg.Session, &sig) != nil {
		return bind{}, errBadBind
	}
	return bind{session: msg.Session, host: host, forwarding: msg.Forwarding}, nil
}

// addBind records a session-bind on this connection: refused if malformed,
// unverified, already bound or one too many, as OpenSSH's agent does. ssh
// carries on after a refusal; its login then asks as one to an unknown
// server.
func (a *gated) addBind(contents []byte) error {
	b, err := parseBind(contents)
	if err != nil {
		return err
	}
	if len(a.binds) >= maxBinds {
		return errBadBind
	}
	for _, old := range a.binds {
		if bytes.Equal(old.session, b.session) {
			return errBadBind
		}
	}
	a.binds = append(a.binds, b)
	return nil
}

// bound is the bind of session on this connection, if any.
func (a *gated) bound(session []byte) (bind, bool) {
	for _, b := range a.binds {
		if bytes.Equal(b.session, session) {
			return b, true
		}
	}
	return bind{}, false
}

// forwardedTo is the host the agent was forwarded to over this connection,
// if it was.
func (a *gated) forwardedTo() (ssh.PublicKey, bool) {
	for _, b := range a.binds {
		if b.forwarding {
			return b.host, true
		}
	}
	return nil, false
}

// server names the holder of host for the popup, from the user's
// known_hosts on the host - never the sandbox's, which sandboxed code can
// write. Hashed entries can't be read back to a name, so claimed (the host
// the client's command line names, unverified) is tried against them: it is
// only shown when the entry under that name is host's.
func (g *Guard) server(host ssh.PublicKey, claimed string) string {
	fp := ssh.FingerprintSHA256(host)
	data, err := os.ReadFile(g.KnownHosts)
	if err != nil {
		return "a host whose key isn't in your known_hosts (" + fp + ")"
	}
	blob := host.Marshal()
	var names []string
	hashed := false
	for len(data) > 0 {
		marker, hosts, key, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			break
		}
		data = rest
		if !bytes.Equal(key.Marshal(), blob) {
			continue
		}
		if marker == "revoked" {
			return "a host whose key your known_hosts REVOKES (" + fp + ")"
		}
		if marker != "" {
			continue
		}
		for _, h := range hosts {
			switch {
			case strings.HasPrefix(h, "|"):
				hashed = true
				if claimed != "" && hashedMatch(h, claimed) && !slices.Contains(names, claimed) {
					names = append(names, claimed)
				}
			case strings.HasPrefix(h, "!"):
			case !slices.Contains(names, h):
				names = append(names, h)
			}
		}
	}
	switch {
	case len(names) > 0:
		return strings.Join(names, ", ") + ", by its host key in your known_hosts"
	case hashed:
		return "a host with a hashed entry in your known_hosts (" + fp + ")"
	}
	return "a host whose key isn't in your known_hosts (" + fp + ")"
}

// hashedMatch says whether the hashed known_hosts pattern (|1|salt|hash)
// is that of host, a name as known_hosts writes it.
func hashedMatch(pattern, host string) bool {
	parts := strings.Split(pattern, "|")
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[2])
	want, err2 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(host))
	return hmac.Equal(mac.Sum(nil), want)
}

// sshOptsWithArg are ssh(1)'s options that take an argument.
const sshOptsWithArg = "BbcDEeFIiJLlmOoPpQRSWw"

// sshDestination is the server ssh's command line args name, as
// known_hosts writes it ("host" or "[host]:port"); "" if args aren't an ssh
// command line. Only a claim: the popup trusts it no further than a
// known_hosts entry under that name with the bound host key.
func sshDestination(args []string) string {
	if len(args) == 0 || filepath.Base(args[0]) != "ssh" {
		return ""
	}
	dest, port := "", ""
	opt := func(o byte, val string) {
		switch {
		case o == 'p':
			port = val
		case o == 'o':
			if k, v, ok := strings.Cut(val, "="); ok && strings.EqualFold(strings.TrimSpace(k), "port") {
				port = strings.TrimSpace(v)
			}
		}
	}
	for i := 1; i < len(args) && dest == ""; i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				dest = args[i+1]
			}
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			dest = arg
			break
		}
		for j := 1; j < len(arg); j++ {
			if strings.IndexByte(sshOptsWithArg, arg[j]) < 0 {
				continue
			}
			val := arg[j+1:]
			if val == "" && i+1 < len(args) {
				i++
				val = args[i]
			}
			opt(arg[j], val)
			break
		}
	}
	if rest, ok := strings.CutPrefix(dest, "ssh://"); ok {
		dest, _, _ = strings.Cut(rest, "/")
		if at := strings.LastIndexByte(dest, '@'); at >= 0 {
			dest = dest[at+1:]
		}
		if h, p, err := net.SplitHostPort(dest); err == nil {
			dest, port = h, p
		}
	} else if at := strings.LastIndexByte(dest, '@'); at >= 0 {
		dest = dest[at+1:]
	}
	if dest == "" {
		return ""
	}
	if port == "" {
		port = "22"
	}
	if port == "22" {
		return dest
	}
	return "[" + dest + "]:" + port
}

// serverLines are the popup's lines on the server a login with session is
// for, given the client's command line args, and the scope an "always"
// answer to it covers: logins to that server's host key, by the same route.
// False without a bind for session.
func (a *gated) serverLines(session []byte, args []string) (lines, scope string, ok bool) {
	b, ok := a.bound(session)
	if !ok {
		return "", "", false
	}
	scope = "login to " + string(b.host.Marshal())
	claimed := sshDestination(args)
	if fwd, forwarded := a.forwardedTo(); forwarded {
		// The login is a remote ssh's, through the agent the local one -
		// whose command line the popup shows - forwarded to fwd.
		lines = "  server:   " + popup.CleanLimit(a.guard.server(b.host, ""), displayLimit) + "\n" +
			"  through:  " + popup.CleanLimit("your agent, forwarded to "+a.guard.server(fwd, claimed), displayLimit) + "\n"
		return lines, scope + " through " + string(fwd.Marshal()), true
	}
	return "  server:   " + popup.CleanLimit(a.guard.server(b.host, claimed), displayLimit) + "\n", scope, true
}
