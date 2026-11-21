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
	"unicode"

	"github.com/mgnsk/sandbox/internal/popup"
)

// Peer is who connected: their working directory and command line, each
// "unknown" when it can't be read.
type Peer struct {
	Cwd, Cmdline string
	// Its session, when it has a controlling terminal; 0 without one, or
	// when it can't be read. See popup.Request.
	Session int
}

// Lines are a popup's lines saying who p is, each cut to limit characters.
func (p Peer) Lines(limit int) string {
	return "  cwd:      " + popup.CleanLimit(p.Cwd, limit) + "\n" +
		"  command:  " + popup.CleanLimit(p.Cmdline, limit) + "\n"
}

// Describe gives the process on the other end of conn.
//
// SO_PEERCRED gives an authentic pid, but only as of connect() - and /proc
// here is the host's. Sampled lazily, at the moment a request needs a popup,
// a peer that has since exited may have had its pid reused by an unrelated
// host process, whose command line the popup would then attribute the
// request to. So a guard calls this once up front, while the peer is
// provably alive on the other end.
func Describe(conn net.Conn) Peer {
	p := Peer{Cwd: "unknown", Cmdline: "unknown"}
	pid, err := pid(conn)
	if err != nil {
		return p
	}
	proc := "/proc/" + strconv.Itoa(pid)
	if cwd, err := os.Readlink(proc + "/cwd"); err == nil {
		p.Cwd = cwd
	}
	if data, err := os.ReadFile(proc + "/cmdline"); err == nil && len(data) > 0 {
		p.Cmdline = Cmdline(bytes.Split(bytes.TrimSuffix(data, []byte{0}), []byte{0}))
	}
	if data, err := os.ReadFile(proc + "/stat"); err == nil {
		p.Session = session(string(data))
	}
	return p
}

// session is the session of the process whose /proc/PID/stat is stat, if it
// has a controlling terminal; else 0.
func session(stat string) int {
	// After the command's name, which may itself hold spaces and brackets:
	// state, ppid, pgrp, session, tty_nr.
	at := strings.LastIndexByte(stat, ')')
	if at < 0 {
		return 0
	}
	fields := strings.Fields(stat[at+1:])
	if len(fields) < 5 {
		return 0
	}
	sid, err1 := strconv.Atoi(fields[3])
	tty, err2 := strconv.Atoi(fields[4])
	if err1 != nil || err2 != nil || tty == 0 || sid <= 0 {
		return 0
	}
	return sid
}

func pid(conn net.Conn) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, syscall.EINVAL
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err == nil {
		err = credErr
	}
	if err != nil {
		return 0, err
	}
	return int(cred.Pid), nil
}

// Cmdline joins args as a command line to show, Go-quoting those that
// wouldn't read as one plain word.
func Cmdline(args [][]byte) string {
	words := make([]string, len(args))
	for i, arg := range args {
		s := strings.ToValidUTF8(string(arg), "�")
		if s == "" || strings.ContainsFunc(s, needsQuote) {
			s = strconv.Quote(s)
		}
		words[i] = s
	}
	return strings.Join(words, " ")
}

func needsQuote(r rune) bool {
	return unicode.IsSpace(r) || !unicode.IsPrint(r) || strings.ContainsRune(`"'\$`+"`", r)
}
