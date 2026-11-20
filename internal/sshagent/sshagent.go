// Package sshagent is ssh-agent-guard: an SSH agent proxy that gates every
// signature behind a popup.
//
//	sandbox-bin ssh-agent-guard UPSTREAM_SOCKET
//
// It sits between a sandboxed client and the real SSH agent socket. Identity
// listing is forwarded untouched; sign requests reach the real agent after
// the user approves a popup, except commit/tag signatures (see
// gitSignature), which are forwarded without a prompt. Everything else is
// refused here and never forwarded: the rest of the protocol mutates the
// agent, and this proxy's whole job is to keep the sandbox from reaching
// past it. Notably that blocks lock, which would let a sandboxed process lock
// the user's real agent with a password of its choosing, key removal and
// addition, and the open-ended extension channel.
//
// Safe against normal use: ssh(1) treats a refused session-bind@openssh.com
// extension as non-fatal, and `ssh-add -l` / `ssh-keygen -Y sign` (git's ssh
// commit signing) only list and sign.
package sshagent

import (
	"bytes"
	"context"
	"errors"
	"net"
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
	// Ask asks the user to approve a signature; popup.Ask if nil.
	Ask func(name, text string) popup.Answer

	approvals popup.Approvals

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
// signatures without asking, anything else as the popup decides.
func (g *Guard) allow(key ssh.PublicKey, data []byte, who peer.Peer) bool {
	if gitSignature(data) {
		return true
	}
	ask := g.Ask
	if ask == nil {
		ask = func(name, text string) popup.Answer { return popup.AskFrom(name, text, who.Session) }
	}
	return g.approvals.Approve(func() popup.Answer {
		return ask("ssh-agent-guard", "Allow SSH agent to sign?\n\n"+
			"  cwd:      "+popup.CleanLimit(who.Cwd, displayLimit)+"\n"+
			"  command:  "+popup.CleanLimit(who.Cmdline, displayLimit)+"\n"+
			"  comment:  "+popup.CleanLimit(g.comment(key), displayLimit)+"\n")
	})
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
	if !a.guard.allow(key, data, a.peer) {
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
func (a *gated) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// Run serves on the launcher's socket until stopped.
func Run(ctx context.Context, upstream string) error {
	ln, err := guard.Listener()
	if err != nil {
		return err
	}
	g := &Guard{Upstream: upstream}
	if err := guard.Ready(struct{}{}); err != nil {
		return err
	}
	return guard.Serve(ctx, ln, g.Handle)
}
