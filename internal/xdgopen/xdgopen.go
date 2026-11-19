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
)

// xdg-open's own exit codes.
const (
	exitSyntax = 1
	exitFailed = 4
)

// Main runs sandbox-xdg-open with argv.
func Main(argv []string) int {
	if len(argv) != 2 {
		fmt.Fprintln(os.Stderr, "usage: xdg-open <http(s) URL>")
		return exitSyntax
	}
	answer, err := ask(filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "open-url.sock"), argv[1])
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "xdg-open: %v\n", err)
		return exitFailed
	case answer == "ok":
		return 0
	case answer == "":
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
	if _, err := io.WriteString(conn, url+"\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(strings.ToValidUTF8(line, "�")), nil
}
