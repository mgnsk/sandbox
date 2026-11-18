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

// Describe gives the cwd and command line of conn's peer, each "unknown"
// if it can't be read.
//
// SO_PEERCRED gives an authentic pid, but only as of connect() - and /proc
// here is the host's. Sampled lazily, at the moment a request needs a popup,
// a peer that has since exited may have had its pid reused by an unrelated
// host process, whose command line the popup would then attribute the
// request to. So a guard calls this once up front, while the peer is
// provably alive on the other end.
func Describe(conn *net.UnixConn) (cwd, cmdline string) {
	pid, err := PID(conn)
	if err != nil {
		return "unknown", "unknown"
	}
	proc := "/proc/" + strconv.Itoa(pid)
	cwd, err = os.Readlink(proc + "/cwd")
	if err != nil {
		cwd = "unknown"
	}
	return cwd, readCmdline(proc + "/cmdline")
}

func readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return "unknown"
	}
	parts := bytes.Split(bytes.TrimSuffix(data, []byte{0}), []byte{0})
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = Quote(Decode(p))
	}
	return strings.Join(quoted, " ")
}

// Decode reads b as UTF-8, each invalid byte replaced with U+FFFD.
func Decode(b []byte) string {
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
