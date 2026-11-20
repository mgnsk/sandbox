package launcher

import (
	"bufio"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// tty is the controlling terminal, also when stdin and stdout are
// redirected.
type tty struct {
	*os.File
	r *bufio.Reader
}

func openTTY() (*tty, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	return &tty{File: f, r: bufio.NewReaderSize(f, 1)}, nil
}

func (t *tty) readLine() string {
	line, _ := t.r.ReadString('\n')
	return strings.TrimSpace(line)
}

// confirm asks a yes/no question, no being the default. What was typed
// before it's asked is dropped: it wasn't an answer to it.
func (t *tty) confirm(question string) bool {
	_ = unix.IoctlSetInt(int(t.Fd()), unix.TCFLSH, unix.TCIFLUSH)
	_, _ = io.WriteString(t, question)
	switch strings.ToLower(t.readLine()) {
	case "y", "yes":
		return true
	}
	return false
}
