// Package sshagent is ssh-agent-guard: an SSH agent proxy that gates every
// signature behind a popup.
//
//	sandbox-bin ssh-agent-guard UPSTREAM_SOCKET SIGNING_KEYS
//
// It sits between a sandboxed client and the real SSH agent socket. Identity
// listing is forwarded untouched; sign requests reach the real agent after
// the user approves a popup, except commit/tag signatures (see
// gitSignature) with one of SIGNING_KEYS (public keys, a line each), which
// are forwarded without a prompt. The session-bind@openssh.com extension is
// taken here, never forwarded: a login's popup names the server whose host
// key signed its session (see sessionbind.go). Everything else is
// refused here and never forwarded: the rest of the protocol mutates the
// agent, and this proxy's whole job is to keep the sandbox from reaching
// past it. Notably that blocks lock, which would let a sandboxed process lock
// the user's real agent with a password of its choosing, key removal and
// addition, and the open-ended extension channel.
//
// Safe against normal use: ssh(1) treats a refused session-bind as
// non-fatal, and `ssh-add -l` / `ssh-keygen -Y sign` (git's ssh commit
// signing) only list and sign.
package sshagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/peer"
	"github.com/mgnsk/sandbox/internal/popup"
)

const displayLimit = 200

var errRefused = errors.New("refused by ssh-agent-guard")

// Guard proxies clients to the agent at Upstream.
type Guard struct {
	Upstream string
	// SigningKeys are the keys git inside signs commits and tags with:
	// only with these does such a signature need no approval. With any
	// key the agent holds, unasked signatures would let sandboxed code
	// sign commits as the user with a key that was only ever meant to log
	// in somewhere.
	SigningKeys []ssh.PublicKey
	// KnownHosts is the user's known_hosts on the host, naming the servers
	// that logins are to.
	KnownHosts string
	// Ask asks the user to approve a signature; popup.Ask if nil.
	Ask func(popup.Request) popup.Answer

	// Scope -> approvals: a login in a session the client bound has its
	// server's scope (see serverLines), every other signature the "" one.
	// So "always" for one server covers no other, nor anything unbound.
	approvalsMu sync.Mutex
	approvals   map[string]*popup.Approvals

	// Fingerprint -> comment, from the identities the agent listed: shown
	// in the popup, not part of the security boundary.
	mu       sync.Mutex
	comments map[string]string
}

// Handle relays one client connection to the agent.
func (g *Guard) Handle(conn net.Conn) {
	defer conn.Close()
	who := peer.Describe(conn)
	upstream, err := net.Dial("unix", g.Upstream)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = agent.ServeAgent(&gated{guard: g, upstream: agent.NewClient(upstream), peer: who}, conn)
}

func (g *Guard) remember(keys []*agent.Key) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.comments == nil {
		g.comments = map[string]string{}
	}
	for _, k := range keys {
		g.comments[ssh.FingerprintSHA256(k)] = k.Comment
	}
}

func (g *Guard) comment(key ssh.PublicKey) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c := g.comments[ssh.FingerprintSHA256(key)]; c != "" {
		return c
	}
	return "unknown"
}

// allow says whether a signature may be asked of the agent: commit
// signatures with a signing key without asking, anything else as the popup
// decides, showing what: the popup's lines on what is signed. An "always"
// answer covers scope alone.
func (g *Guard) allow(key ssh.PublicKey, data []byte, who peer.Peer, what, scope string) bool {
	if gitSignature(data) && g.signingKey(key) {
		return true
	}
	ask := g.Ask
	if ask == nil {
		ask = popup.Ask
	}
	return g.scoped(scope).Approve(func() popup.Answer {
		return ask(popup.Request{Name: "ssh-agent-guard", Session: who.Session, Text: "Allow SSH agent to sign?\n\n" +
			what +
			"  key:      " + ssh.FingerprintSHA256(key) + "\n" +
			"  comment:  " + popup.CleanLimit(g.comment(key), displayLimit) + "\n" +
			who.Lines(displayLimit)})
	})
}

// scoped are the approvals of scope.
func (g *Guard) scoped(scope string) *popup.Approvals {
	g.approvalsMu.Lock()
	defer g.approvalsMu.Unlock()
	if g.approvals == nil {
		g.approvals = map[string]*popup.Approvals{}
	}
	a := g.approvals[scope]
	if a == nil {
		a = &popup.Approvals{}
		g.approvals[scope] = a
	}
	return a
}

func (g *Guard) signingKey(key ssh.PublicKey) bool {
	blob := key.Marshal()
	for _, k := range g.SigningKeys {
		if bytes.Equal(k.Marshal(), blob) {
			return true
		}
	}
	return false
}

// SSH_MSG_USERAUTH_REQUEST.
const msgUserauthRequest = 50

// signed says what kind of thing data, about to be signed, is: the
// requester chose its content, but not the form a verifier takes it in. A
// login's data begins with its session and names the user, never the
// server; an SSHSIG signature names the namespace its verifier checks.
func signed(data []byte) string {
	if rest, ok := bytes.CutPrefix(data, []byte("SSHSIG")); ok {
		var blob struct {
			Namespace string
			Rest      []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(rest, &blob) == nil {
			if blob.Namespace == "git" {
				return "a git commit or tag, with a key that isn't your signing key"
			}
			return fmt.Sprintf("a signature for %q (ssh-keygen -Y sign)", blob.Namespace)
		}
	}
	if user, _, ok := login(data); ok {
		return fmt.Sprintf("an ssh login as %q, to a server the guard can't know", user)
	}
	return fmt.Sprintf("data of no known kind (%d bytes)", len(data))
}

// login reads data as an ssh login's: the user it names and the session
// it is for.
func login(data []byte) (user string, session []byte, ok bool) {
	var auth struct {
		Session []byte
		Type    byte
		User    string
		Service string
		Method  string
		Rest    []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(data, &auth) == nil && auth.Type == msgUserauthRequest && strings.HasPrefix(auth.Method, "publickey") {
		return auth.User, auth.Session, true
	}
	return "", nil, false
}

// describe is the popup's lines on what data is: for a login in a session
// the client bound, the server it is to, else as signed says; and the scope
// of its approvals.
func (a *gated) describe(data []byte) (what, scope string) {
	if user, session, ok := login(data); ok {
		if lines, scope, ok := a.serverLines(session, a.peer.Args); ok {
			return "  signing:  " + popup.CleanLimit(fmt.Sprintf("an ssh login as %q", user), displayLimit) + "\n" + lines +
				"  always:   covers logins to this server alone\n", scope
		}
	}
	return "  signing:  " + popup.CleanLimit(signed(data), displayLimit) + "\n", ""
}

// gitSignature says whether data is what `ssh-keygen -Y sign -n git` (git
// commit and tag signing with gpg.format=ssh) asks the agent to sign: the
// SSHSIG preamble of PROTOCOL.sshsig with git's namespace. Plain SSH
// authentication (git push/pull over ssh, an interactive session) signs
// session data, never that.
//
// It only spares the popup, never changes what's signed - and only for the
// "git" namespace: any other (e.g. "file") would be an unprompted signature
// for some other verifier.
func gitSignature(data []byte) bool {
	rest, ok := bytes.CutPrefix(data, []byte("SSHSIG"))
	var blob struct {
		Namespace string
		Rest      []byte `ssh:"rest"`
	}
	return ok && ssh.Unmarshal(rest, &blob) == nil && blob.Namespace == "git"
}

// gated is the agent a client sees: listing and gated signing passed on to
// the real one, everything else refused.
type gated struct {
	guard    *Guard
	upstream agent.ExtendedAgent
	peer     peer.Peer
	// The sessions the client bound, in order: ServeAgent handles one
	// request of a connection at a time.
	binds []bind
}

func (a *gated) List() ([]*agent.Key, error) {
	keys, err := a.upstream.List()
	if err == nil {
		a.guard.remember(keys)
	}
	return keys, err
}

func (a *gated) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *gated) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	what, scope := a.describe(data)
	if !a.guard.allow(key, data, a.peer, what, scope) {
		return nil, errRefused
	}
	return a.upstream.SignWithFlags(key, data, flags)
}

func (a *gated) Add(agent.AddedKey) error       { return errRefused }
func (a *gated) Remove(ssh.PublicKey) error     { return errRefused }
func (a *gated) RemoveAll() error               { return errRefused }
func (a *gated) Lock([]byte) error              { return errRefused }
func (a *gated) Unlock([]byte) error            { return errRefused }
func (a *gated) Signers() ([]ssh.Signer, error) { return nil, errRefused }

// Extension handles session-bind here, for the popup, never passing it on:
// the agent's own key restrictions would then apply, refusing logins that
// work now. Every other extension is refused.
func (a *gated) Extension(kind string, contents []byte) ([]byte, error) {
	if kind != sessionBind {
		return nil, agent.ErrExtensionUnsupported
	}
	if err := a.addBind(contents); err != nil {
		return nil, err
	}
	return []byte{agentSuccess}, nil
}

// SSH_AGENT_SUCCESS.
const agentSuccess = 6

// Run serves on the launcher's socket until stopped; signingKeys are public
// keys, a line each.
func Run(ctx context.Context, upstream, signingKeys string) error {
	ln, err := guard.Listener()
	if err != nil {
		return err
	}
	g := &Guard{Upstream: upstream}
	if home, err := os.UserHomeDir(); err == nil {
		g.KnownHosts = filepath.Join(home, ".ssh", "known_hosts")
	}
	for line := range strings.Lines(signingKeys) {
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
			g.SigningKeys = append(g.SigningKeys, key)
		}
	}
	if err := guard.Ready(struct{}{}); err != nil {
		return err
	}
	return guard.Serve(ctx, ln, g.Handle)
}
