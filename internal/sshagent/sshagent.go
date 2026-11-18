// Package sshagent is ssh-agent-guard: an SSH agent proxy that gates every
// sign request behind a popup.
//
//	ssh-agent-guard UPSTREAM_SOCKET LISTEN_SOCKET
//
// It sits between a sandboxed client and the real SSH agent socket. Identity
// listing is forwarded untouched; sign requests reach the real agent after
// the user approves a popup, except commit/tag signatures (identified by the
// SSHSIG magic preamble - see sshsigMagic), which are forwarded without a
// prompt. Every other request type is refused outright - see forwardable.
package sshagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/mgnsk/sandbox/internal/cover"
	"github.com/mgnsk/sandbox/internal/peer"
	"github.com/mgnsk/sandbox/internal/popup"
)

const (
	agentFailure             = 5
	requestIdentities        = 11
	identitiesAnswer         = 12
	signRequest              = 13
	displayLimit             = 200
	unknown                  = "unknown"
	gitNamespace             = "git"
	maxMessageSize    uint32 = 256 * 1024
)

// forwardable says whether a request type may reach the real agent at all.
// Everything else is answered with SSH_AGENT_FAILURE here and never
// forwarded: the rest of the protocol mutates the agent, and this proxy's
// whole job is to keep the sandbox from reaching past it. Notably that blocks
// SSH_AGENTC_LOCK (22), which would otherwise let a sandboxed process lock
// the user's real agent with a password of its choosing, and
// REMOVE_IDENTITY/REMOVE_ALL_IDENTITIES (18/19), ADD_IDENTITY (17/25), the
// smartcard calls (20/21/26) and the open-ended SSH_AGENTC_EXTENSION channel
// (27).
//
// Safe against normal use: ssh(1) treats a refused session-bind@openssh.com
// extension as non-fatal, and `ssh-add -l` / `ssh-keygen -Y sign` (git's ssh
// commit signing) only ever send these two types.
func forwardable(msgType byte) bool {
	return msgType == requestIdentities || msgType == signRequest
}

// sshsigMagic is the preamble OpenSSH's `ssh-keygen -Y sign` wraps the
// to-be-signed data in (see PROTOCOL.sshsig) before it ever reaches the agent
// - this is how git commit/tag signing (gpg.format=ssh) signs. Plain SSH
// transport authentication (git push/pull/clone over ssh, an interactive ssh
// session) signs the session data directly and never carries it.
//
// It only changes whether this request needs a popup, never what upstream is
// asked to sign - and only for the "git" namespace git signs with: any other
// namespace (e.g. "file") would be an unprompted signature for some other
// verifier.
var sshsigMagic = []byte("SSHSIG")

var (
	approvals popup.Approvals

	// Fingerprint -> comment, from the identities the agent listed: display
	// enrichment for the popup, not part of the security boundary.
	identityMu       sync.Mutex
	identityComments = map[string]string{}
)

var errShort = errors.New("message too short")

// readString reads a length-prefixed string from buf at offset.
func readString(buf []byte, offset int) ([]byte, int, error) {
	if offset+4 > len(buf) {
		return nil, 0, errShort
	}
	n := int(binary.BigEndian.Uint32(buf[offset:]))
	offset += 4
	if n > len(buf)-offset {
		return nil, 0, errShort
	}
	return buf[offset : offset+n], offset + n, nil
}

// sshsigNamespace is the namespace of an SSHSIG signed-data blob (the magic,
// then the namespace as a string), or ok=false if data isn't one.
func sshsigNamespace(data []byte) (string, bool) {
	if !bytes.HasPrefix(data, sshsigMagic) {
		return "", false
	}
	ns, _, err := readString(data, len(sshsigMagic))
	if err != nil {
		return "", false
	}
	return string(ns), true
}

// fingerprint is the SHA256 fingerprint of a key blob, as `ssh-keygen -lf`
// shows it.
func fingerprint(keyBlob []byte) string {
	digest := sha256.Sum256(keyBlob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

// cacheIdentities records fingerprint -> comment from an identities answer,
// as far as it parses.
func cacheIdentities(payload []byte) {
	if len(payload) < 5 {
		return
	}
	n := binary.BigEndian.Uint32(payload[1:])
	offset := 5
	for range n {
		keyBlob, next, err := readString(payload, offset)
		if err != nil {
			return
		}
		comment, next, err := readString(payload, next)
		if err != nil {
			return
		}
		offset = next
		identityMu.Lock()
		identityComments[fingerprint(keyBlob)] = peer.Decode(comment)
		identityMu.Unlock()
	}
}

// readFrame reads one length-prefixed agent message; an error at EOF or an
// oversized length, which is never read.
func readFrame(r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n > maxMessageSize {
		return nil, fmt.Errorf("message of %d bytes", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	buf := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(payload)), uint32(len(payload)))
	_, err := w.Write(append(buf, payload...))
	return err
}

// confirm asks in a popup whether to approve a sign request.
func confirm(cwd, cmdline, comment string) string {
	text := "Allow SSH agent to sign?\n\n" +
		"  cwd:      " + popup.CleanLimit(cwd, displayLimit) + "\n" +
		"  command:  " + popup.CleanLimit(cmdline, displayLimit) + "\n" +
		"  comment:  " + popup.CleanLimit(comment, displayLimit) + "\n"
	return popup.Ask("ssh-agent-guard", text)
}

// allowSign says whether a sign request may reach the agent: commit
// signatures without asking, anything else as the popup decides.
func allowSign(payload []byte, cwd, cmdline string) bool {
	keyFP := unknown
	var data []byte
	keyBlob, offset, err := readString(payload, 1)
	if err == nil {
		data, _, err = readString(payload, offset)
	}
	if err == nil {
		keyFP = fingerprint(keyBlob)
	} else {
		data = nil
	}
	if ns, ok := sshsigNamespace(data); ok && ns == gitNamespace {
		return true
	}
	identityMu.Lock()
	comment, ok := identityComments[keyFP]
	identityMu.Unlock()
	if !ok || comment == "" {
		comment = unknown
	}
	return approvals.Approve(func() string { return confirm(cwd, cmdline, comment) })
}

// handle relays one client connection to the upstream agent.
func handle(client *net.UnixConn, upstreamPath string) {
	defer client.Close()
	cwd, cmdline := peer.Describe(client)

	upstream, err := net.Dial("unix", upstreamPath)
	if err != nil {
		return
	}
	defer upstream.Close()

	fail := []byte{agentFailure}
	for {
		payload, err := readFrame(client)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			continue
		}
		msgType := payload[0]
		if !forwardable(msgType) ||
			msgType == signRequest && !allowSign(payload, cwd, cmdline) {
			if writeFrame(client, fail) != nil {
				return
			}
			continue
		}
		if writeFrame(upstream, payload) != nil {
			return
		}
		response, err := readFrame(upstream)
		if err != nil {
			return
		}
		if msgType == requestIdentities && len(response) > 0 && response[0] == identitiesAnswer {
			cacheIdentities(response)
		}
		if writeFrame(client, response) != nil {
			return
		}
	}
}

// Main listens on argv[2], proxying each connection to argv[1].
func Main(argv []string) int {
	if len(argv) != 3 {
		fmt.Fprintln(os.Stderr, "usage: ssh-agent-guard UPSTREAM_SOCKET LISTEN_SOCKET")
		return 2
	}
	upstreamPath, listenPath := argv[1], argv[2]
	cover.DieOnSignals()

	if _, err := os.Lstat(listenPath); err == nil {
		_ = os.Remove(listenPath)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: listenPath, Net: "unix"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent-guard: %v\n", err)
		return 1
	}
	ln.SetUnlinkOnClose(false)
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-agent-guard: %v\n", err)
			return 1
		}
		go handle(conn, upstreamPath)
	}
}
