// Package popuprelay is the launcher's terminal: the sandbox runs behind a
// pty of its own, and the guards' approval popups are drawn on the real
// terminal in between.
//
// Only the launcher holds the real terminal. The sandbox gets the slave side
// of a fresh pty, and the launcher copies bytes both ways - except while a
// popup is up: then keys go to the popup alone and the sandbox's output is
// held back. So nothing in the sandbox can type into a popup, draw over it
// or read what's typed there, and it works wherever a terminal does (over
// ssh too), with nothing to install.
//
// A popup takes over the whole screen. When the sandbox is on the main
// screen it's drawn on the alternate one, and switching back restores the
// sandbox's screen as it was. When the sandbox is on the alternate screen
// itself (vim, less, ...), it's drawn there, and afterwards the pty is
// resized away and back, which has a full-screen program redraw.
//
// Guards ask over a unix socket in a private temp dir (see package popup):
// a JSON {"name", "text"} request, answered with "once", "always" or "no".
// Requests are shown one at a time, in order. Without a usable terminal
// there is no socket, and popup.Ask answers no.
package popuprelay

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// Keys typed in this long after a popup appears are dropped: they were
	// meant for the sandbox, typed before the popup could be seen.
	// Otherwise a sandbox could time a request to catch a "y<Enter>" typed
	// into its own prompt.
	grace      = 500 * time.Millisecond
	maxRequest = 1 << 20
	// Sandbox output held while a popup is up, past which the pty is no
	// longer read (the sandbox blocks on writing).
	maxPending = 1 << 20
	// How long the pty stays at the other size when nudging a redraw.
	nudge = 50 * time.Millisecond
)

// Usable says whether there's a terminal to relay and show popups on.
func Usable() bool {
	return isatty(0) && isatty(1)
}

func isatty(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// Listen opens the socket the guards ask on, in the launcher's private temp
// dir.
func Listen(path string) (*net.UnixListener, error) {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

type request struct {
	conn       net.Conn
	name, text string
}

// jsonString is a request field as Python's str() of it.
func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// readRequest reads a guard's request; ok=false if it's malformed.
func readRequest(conn net.Conn) (name, text string, ok bool) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, err := io.ReadAll(io.LimitReader(conn, maxRequest+1))
	if err != nil || len(data) > maxRequest {
		return "", "", false
	}
	var req map[string]json.RawMessage
	if json.Unmarshal(data, &req) != nil {
		return "", "", false
	}
	rawName, ok1 := req["name"]
	rawText, ok2 := req["text"]
	if !ok1 || !ok2 {
		return "", "", false
	}
	return jsonString(rawName), jsonString(rawText), true
}

func reply(conn net.Conn, answer string) {
	_, _ = conn.Write([]byte(answer))
	conn.Close()
}

type winsize = unix.Winsize

func getSize(fd int) (*winsize, error) { return unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ) }
func setSize(fd int, ws *winsize)      { _ = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws) }

// Relay runs a command on a pty and relays the terminal, with popups.
type Relay struct {
	listener *net.UnixListener
	fd, out  int

	ttyOK     bool
	masterEOF bool
	master    int
	modes     modes
	toChild   []byte
	pending   []byte
	queue     []request
	popup     *pop
	conn      net.Conn
	screen    bool // The popup screen is open.
	drewOnAlt bool
	resized   bool
	timers    map[string]time.Time

	wakeR, wakeW int
	mu           sync.Mutex
	requests     []request
	winch        bool
	cmd          *exec.Cmd
}

// New makes a relay for the guards asking on listener.
func New(listener *net.UnixListener) *Relay {
	return &Relay{listener: listener, fd: 0, out: 1, ttyOK: true, master: -1,
		modes: modes{cursor: true}, timers: map[string]time.Time{}}
}

// Signal handles a signal the launcher gets while the relay runs: SIGINT is
// for the sandbox (it's raw mode here, so it only comes from kill), SIGTERM
// and SIGHUP go to it.
func (r *Relay) Signal(sig os.Signal) {
	r.mu.Lock()
	cmd := r.cmd
	r.mu.Unlock()
	if sig != syscall.SIGINT && cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(sig)
	}
}

func (r *Relay) wake() {
	_, _ = unix.Write(r.wakeW, []byte{0})
}

// openPty opens a pty pair: the master, and the slave as a file.
func openPty() (int, *os.File, error) {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		unix.Close(master)
		return -1, nil, err
	}
	n, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		unix.Close(master)
		return -1, nil, err
	}
	name := "/dev/pts/" + strconv.Itoa(n)
	slave, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(master)
		return -1, nil, err
	}
	return master, os.NewFile(uintptr(slave), name), nil
}

// makeRaw is Python's tty.cfmakeraw.
func makeRaw(t unix.Termios) *unix.Termios {
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.IGNPAR | unix.PARMRK | unix.INPCK |
		unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXANY | unix.IXOFF
	t.Oflag &^= unix.OPOST
	t.Cflag &^= unix.PARENB | unix.CSIZE
	t.Cflag |= unix.CS8
	t.Lflag &^= unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHONL | unix.ICANON | unix.IEXTEN |
		unix.ISIG | unix.NOFLSH | unix.TOSTOP
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	return &t
}

// Run runs argv on a pty, relaying the terminal; its exit status (negative
// for a signal, as Python's).
func (r *Relay) Run(argv []string) (int, error) {
	attrs, err := unix.IoctlGetTermios(r.fd, unix.TCGETS)
	if err != nil {
		return 0, err
	}
	master, slave, err := openPty()
	if err != nil {
		return 0, err
	}
	_ = unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, attrs)
	if ws, err := getSize(r.fd); err == nil {
		setSize(int(slave.Fd()), ws)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	err = cmd.Start()
	slave.Close()
	if err != nil {
		unix.Close(master)
		return 0, err
	}
	r.mu.Lock()
	r.cmd = cmd
	r.mu.Unlock()
	r.master = master
	_ = unix.SetNonblock(master, true)

	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return 0, err
	}
	r.wakeR, r.wakeW = pipe[0], pipe[1]
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-winch:
				r.mu.Lock()
				r.winch = true
				r.mu.Unlock()
				r.wake()
			case <-stop:
				return
			}
		}
	}()
	go r.accept()

	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		return 0, err
	}
	_ = unix.IoctlSetTermios(r.fd, unix.TCSETS, makeRaw(*attrs))

	r.loop(pidfd)
	r.drain()

	for _, c := range append([]net.Conn{r.conn}, r.queuedConns()...) {
		if c != nil {
			reply(c, "no")
		}
	}
	r.popup, r.conn, r.queue = nil, nil, nil
	if r.screen {
		r.closeScreen()
	}
	_ = unix.IoctlSetTermios(r.fd, unix.TCSETSW, attrs)
	signal.Stop(winch)
	close(stop)
	r.listener.Close()
	for _, fd := range []int{pidfd, r.wakeR, r.wakeW, master} {
		unix.Close(fd)
	}
	_ = cmd.Wait()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int(ws.Signal()), nil
	}
	return cmd.ProcessState.ExitCode(), nil
}

func (r *Relay) queuedConns() []net.Conn {
	var out []net.Conn
	for _, q := range r.queue {
		out = append(out, q.conn)
	}
	r.mu.Lock()
	for _, q := range r.requests {
		out = append(out, q.conn)
	}
	r.requests = nil
	r.mu.Unlock()
	return out
}

// accept reads the guards' requests, one at a time, in order, and hands
// them to the loop.
func (r *Relay) accept() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		name, text, ok := readRequest(conn)
		if !ok {
			conn.Close()
			continue
		}
		r.mu.Lock()
		r.requests = append(r.requests, request{conn, name, text})
		r.mu.Unlock()
		r.wake()
	}
}

func (r *Relay) loop(pidfd int) {
	for {
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}, {Fd: int32(r.wakeR), Events: unix.POLLIN}}
		ttyAt, masterAt := -1, -1
		if r.ttyOK {
			ttyAt = len(fds)
			fds = append(fds, unix.PollFd{Fd: int32(r.fd), Events: unix.POLLIN})
		}
		if ev := r.masterEvents(); ev != 0 {
			masterAt = len(fds)
			fds = append(fds, unix.PollFd{Fd: int32(r.master), Events: ev})
		}
		timeout := -1
		if len(r.timers) > 0 {
			next := time.Time{}
			for _, at := range r.timers {
				if next.IsZero() || at.Before(next) {
					next = at
				}
			}
			timeout = max(int(time.Until(next)/time.Millisecond)+1, 0)
		}
		if _, err := unix.Poll(fds, timeout); err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
		if fds[0].Revents != 0 {
			return
		}
		if ttyAt >= 0 && fds[ttyAt].Revents != 0 {
			r.onTTY()
		}
		if masterAt >= 0 {
			if fds[masterAt].Revents&unix.POLLOUT != 0 {
				r.writeChild()
			}
			if fds[masterAt].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
				r.readChild()
			}
		}
		if fds[1].Revents != 0 {
			r.onWake()
		}
		now := time.Now()
		for name, at := range r.timers {
			if !at.After(now) {
				delete(r.timers, name)
				switch name {
				case "unnudge":
					if ws, err := getSize(r.fd); err == nil {
						setSize(r.master, ws)
					}
				case "ready":
					if r.popup != nil {
						r.draw()
					}
				}
			}
		}
	}
}

func (r *Relay) onWake() {
	var buf [512]byte
	for {
		if n, _ := unix.Read(r.wakeR, buf[:]); n <= 0 {
			break
		}
	}
	r.mu.Lock()
	winch := r.winch
	r.winch = false
	requests := r.requests
	r.requests = nil
	r.mu.Unlock()
	if winch {
		r.onResize()
	}
	for _, req := range requests {
		r.queue = append(r.queue, req)
		if r.popup == nil {
			r.nextPopup()
		}
	}
}

// -- the sandbox's side --

// masterEvents is what to watch the pty for: reading unless the held output
// is full, writing while there's input for it.
func (r *Relay) masterEvents() int16 {
	if r.masterEOF {
		return 0
	}
	var ev int16
	if len(r.pending) < maxPending {
		ev |= unix.POLLIN
	}
	if len(r.toChild) > 0 {
		ev |= unix.POLLOUT
	}
	return ev
}

func (r *Relay) writeChild() {
	n, err := unix.Write(r.master, r.toChild)
	if errors.Is(err, unix.EAGAIN) {
		return
	}
	if err != nil {
		n = len(r.toChild)
	}
	r.toChild = r.toChild[n:]
}

func (r *Relay) readChild() {
	buf := make([]byte, 65536)
	n, err := unix.Read(r.master, buf)
	if errors.Is(err, unix.EAGAIN) {
		return
	}
	if err != nil || n <= 0 {
		// Every slave fd closed; the exit follows.
		r.masterEOF = true
		return
	}
	if r.screen {
		r.pending = append(r.pending, buf[:n]...)
	} else {
		r.show(buf[:n])
	}
}

// drain takes what the sandbox wrote before it exited.
func (r *Relay) drain() {
	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(r.master, buf)
		if err != nil || n <= 0 {
			return
		}
		if r.screen {
			r.pending = append(r.pending, buf[:n]...)
		} else {
			r.show(buf[:n])
		}
	}
}

// -- the terminal's side --

func (r *Relay) write(data []byte) {
	if !r.ttyOK {
		return
	}
	for len(data) > 0 {
		n, err := unix.Write(r.out, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			r.ttyOK = false
			return
		}
		data = data[n:]
	}
}

// show puts sandbox output onto the terminal.
func (r *Relay) show(data []byte) {
	r.modes.feed(data)
	r.write(data)
}

func (r *Relay) onTTY() {
	buf := make([]byte, 4096)
	n, err := unix.Read(r.fd, buf)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return
	}
	if err != nil || n <= 0 {
		// Hung up: nothing more to relay, and no one to answer popups.
		r.ttyOK = false
		if r.popup != nil {
			r.answer("no")
		}
		return
	}
	if r.popup != nil {
		if answer := r.popup.feed(buf[:n], time.Now()); answer != "" {
			r.answer(answer)
		} else {
			r.draw()
		}
		return
	}
	r.toChild = append(r.toChild, buf[:n]...)
}

func (r *Relay) onResize() {
	ws, err := getSize(r.fd)
	if err != nil {
		return
	}
	if !r.screen {
		setSize(r.master, ws)
		return
	}
	r.resized = true
	if r.popup != nil {
		r.popup.resize(int(ws.Row), int(ws.Col))
		r.draw()
	}
}

// -- popups --

func (r *Relay) nextPopup() {
	for len(r.queue) > 0 {
		req := r.queue[0]
		r.queue = r.queue[1:]
		if !r.ttyOK {
			reply(req.conn, "no")
			continue
		}
		if !r.screen {
			r.openScreen()
		}
		rows, cols := 24, 80
		if ws, err := getSize(r.fd); err == nil {
			rows, cols = int(ws.Row), int(ws.Col)
		}
		r.popup = newPop(req.name, req.text, rows, cols, time.Now(), grace)
		r.conn = req.conn
		r.timers["ready"] = r.popup.readyAt
		r.draw()
		return
	}
	if r.screen {
		r.closeScreen()
	}
}

func (r *Relay) answer(answer string) {
	reply(r.conn, answer)
	r.popup, r.conn = nil, nil
	delete(r.timers, "ready")
	r.nextPopup()
}

func (r *Relay) draw() {
	r.write(r.popup.render(time.Now()))
}

func (r *Relay) openScreen() {
	r.drewOnAlt = r.modes.alt
	r.resized = false
	// 1049 saves the cursor and attributes on the way in and restores them
	// on the way out; on the alternate screen already, \e7 does.
	if r.drewOnAlt {
		r.write([]byte("\x1b7"))
	} else {
		r.write([]byte("\x1b[?1049h"))
	}
	r.screen = true
}

func (r *Relay) closeScreen() {
	if r.drewOnAlt {
		r.write([]byte("\x1b[0m\x1b[H\x1b[2J\x1b8"))
	} else {
		r.write([]byte("\x1b[0m\x1b[?1049l"))
	}
	if r.modes.cursor {
		r.write([]byte("\x1b[?25h"))
	} else {
		r.write([]byte("\x1b[?25l"))
	}
	r.screen = false
	if len(r.pending) > 0 {
		r.show(r.pending)
		r.pending = nil
	}
	ws, err := getSize(r.fd)
	if err != nil {
		return
	}
	if r.resized {
		setSize(r.master, ws)
	} else if r.drewOnAlt {
		// The same size again wouldn't signal; a column less, briefly, has
		// the program inside redraw what the popup covered.
		other := *ws
		if other.Col > 1 {
			other.Col--
		} else {
			other.Col = 2
		}
		setSize(r.master, &other)
		r.timers["unnudge"] = time.Now().Add(nudge)
	}
}
