// Package popup is the guards' side of the approval popup the launcher
// shows.
//
// The launcher owns the terminal the sandbox runs on and listens on a socket
// only the guards know: $SANDBOX_POPUP_SOCKET, in a private temp dir that's
// never bound in. A guard sends a JSON Request and gets the user's answer
// back: "once", "always", or anything else for no.
//
// Each guard runs on the host, one process per sandbox, for as long as that
// sandbox does. So an Approvals held in a guard's memory is what "always in
// this sandbox" means: nothing is written down, and the next sandbox asks
// again.
package popup

import (
	"encoding/json/v2"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"unicode"
)

// Env names the launcher's popup socket.
const Env = "SANDBOX_POPUP_SOCKET"

// Request is what a guard asks: name says who asks, text is shown as is
// (after Clean), never run.
type Request struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

// Answer is the user's answer to a popup.
type Answer string

const (
	No     Answer = "no"
	Once   Answer = "once"
	Always Answer = "always"
)

// The longest answer read; anything longer is a no.
const maxAnswer = 64

// ParseAnswer reads an answer off the wire; anything unknown is No.
func ParseAnswer(s string) Answer {
	switch a := Answer(s); a {
	case Once, Always:
		return a
	}
	return No
}

// Ask shows text in a popup at the socket in $SANDBOX_POPUP_SOCKET and
// blocks for the answer: No also when there's no terminal to ask on, or on
// any failure.
func Ask(name, text string) Answer {
	path := os.Getenv(Env)
	if path == "" {
		return No
	}
	return AskAt(path, Request{Name: name, Text: text})
}

// AskAt asks at the popup socket at path.
func AskAt(path string, req Request) Answer {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return No
	}
	defer conn.Close()
	if err := json.MarshalWrite(conn, req); err != nil {
		return No
	}
	if err := conn.CloseWrite(); err != nil {
		return No
	}
	answer, err := io.ReadAll(io.LimitReader(conn, maxAnswer+1))
	if err != nil || len(answer) > maxAnswer {
		return No
	}
	return ParseAnswer(string(answer))
}

// Approvals are one guard's approvals for the life of its process.
type Approvals struct {
	mu     sync.Mutex
	always bool
}

// Approve says whether to let a request through, calling ask for the user's
// answer unless they have already answered Always.
//
// The lock is held across the popup: one at a time, and requests queued
// behind an Always answer see it instead of popping up themselves.
func (a *Approvals) Approve(ask func() Answer) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.always {
		return true
	}
	switch ask() {
	case Always:
		a.always = true
		return true
	case Once:
		return true
	}
	return false
}

// Clean replaces non-printable characters (terminal escapes, bidi
// overrides, line breaks) with "?", for a field shown on one line.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}

// CleanText is Clean, keeping line breaks.
func CleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}

// CleanLimit is Clean, cut to limit characters with an ellipsis.
func CleanLimit(s string, limit int) string {
	r := []rune(Clean(s))
	if len(r) <= limit {
		return string(r)
	}
	return string(r[:limit]) + "…"
}
