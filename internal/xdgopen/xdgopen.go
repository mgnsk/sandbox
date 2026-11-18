// Package xdgopen is sandbox-xdg-open, xdg-open inside a sandbox, at
// /usr/bin/xdg-open.
//
// It sends the URL to open-url-guard on the host, which does all the
// checking: anything in the sandbox can talk to that socket directly.
package xdgopen

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// xdg-open's own exit codes.
const (
	exitSyntax = 1
	exitFailed = 4
)

func strerror(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s := errno.Error()
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return err.Error()
}

// Main runs sandbox-xdg-open with argv.
func Main(argv []string) int {
	if len(argv) != 2 {
		fmt.Fprintln(os.Stderr, "usage: xdg-open <http(s) URL>")
		return exitSyntax
	}

	path := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "open-url.sock")
	answer, err := ask(path, argv[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdg-open: %s: %s\n", path, strerror(err))
		return exitFailed
	}
	if answer == "ok" {
		return 0
	}
	if answer == "" {
		answer = "no answer from open-url-guard"
	}
	fmt.Fprintf(os.Stderr, "xdg-open: %s\n", answer)
	return exitFailed
}

// ask sends url to the guard at path and reads its one-line answer, which
// takes as long as the popup is up.
func ask(path, url string) (string, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(url + "\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(strings.ToValidUTF8(line, "�")), nil
}
