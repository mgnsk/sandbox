// Package peer describes the process on the other end of a guard's socket,
// for its popups.
package peer

import (
	"bytes"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

// PID of the process on the other end of a connected AF_UNIX socket.
func PID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(cred.Pid), nil
}

// Describe gives the cwd and command line of conn's peer, sampled while it
// still holds the connection, or "unknown" for both.
//
// The peer's /proc entries are only a hint for the user: a process can
// change its own command line, and the pid may be reused once it exits.
func Describe(conn *net.UnixConn) (cwd, cmdline string) {
	pid, err := PID(conn)
	if err != nil {
		return "unknown", "unknown"
	}
	proc := "/proc/" + strconv.Itoa(pid)
	cwd, err = os.Readlink(proc + "/cwd")
	if err != nil {
		return "unknown", "unknown"
	}
	data, err := os.ReadFile(proc + "/cmdline")
	if err != nil {
		return "unknown", "unknown"
	}
	parts := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = Quote(decode(p))
	}
	return cwd, strings.Join(quoted, " ")
}

// decode reads b as UTF-8, each invalid byte replaced with U+FFFD.
func decode(b []byte) string {
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		sb.WriteRune(r)
		b = b[n:]
	}
	return sb.String()
}

// Quote quotes s for a POSIX shell when it needs it, like Python's
// shlex.quote.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		if !(c < utf8.RuneSelf && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || strings.ContainsRune("@%+=:,./-_", c))) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
