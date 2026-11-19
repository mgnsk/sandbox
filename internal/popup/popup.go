// Package popup is the guards' side of the approval popup the launcher
// shows.
//
// The launcher owns the terminal the sandbox runs on and listens on a socket
// only the guards know: $SANDBOX_POPUP_SOCKET, in a private temp dir that's
// never bound in. A guard sends the text to show and gets the user's answer
// back.
//
// Each guard runs on the host, one process per sandbox, for as long as that
// sandbox does. So an Approvals held in a guard's memory is what "always in
// this sandbox" means: nothing is written down, and the next sandbox asks
// again.
package popup

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"unicode"
)

// Env names the launcher's popup socket.
const Env = "SANDBOX_POPUP_SOCKET"

// The longest answer read; anything longer is a no.
const maxAnswer = 64

// Ask shows text in a popup and blocks for the answer: "once", "always", or
// "" for no / no terminal to ask on / any failure.
//
// The text is only ever drawn by the launcher, never run: it's sent as data
// over the socket, and the launcher replaces anything non-printable.
func Ask(name, text string) string {
	path := os.Getenv(Env)
	if path == "" {
		return ""
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return ""
	}
	defer conn.Close()
	req, err := json.Marshal(map[string]string{"name": name, "text": text})
	if err != nil {
		return ""
	}
	if _, err := conn.Write(req); err != nil {
		return ""
	}
	if err := conn.CloseWrite(); err != nil {
		return ""
	}
	answer, err := io.ReadAll(io.LimitReader(conn, maxAnswer+1))
	if err != nil || len(answer) > maxAnswer {
		return ""
	}
	switch a := string(answer); a {
	case "once", "always":
		return a
	}
	return ""
}

// Approvals are one guard's approvals for the life of its process.
type Approvals struct {
	mu     sync.Mutex
	always bool
}

// Approve says whether to let a request through, calling ask for the user's
// answer unless they have already answered "always".
//
// The lock is held across the popup: one at a time, and requests queued
// behind an "always" answer see it instead of popping up themselves.
func (a *Approvals) Approve(ask func() string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.always {
		return true
	}
	answer := ask()
	if answer == "always" {
		a.always = true
	}
	return answer == "once" || answer == "always"
}

// Clean replaces non-printable characters (e.g. terminal escapes) with "?"
// for safe display.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}

// CleanLimit is Clean, then cut to limit characters with an ellipsis.
func CleanLimit(s string, limit int) string {
	r := []rune(Clean(s))
	if len(r) <= limit {
		return string(r)
	}
	return string(r[:limit]) + "…"
}
