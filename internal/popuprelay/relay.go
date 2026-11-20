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
// Guards ask over a unix socket in a private temp dir (see package popup).
// Requests are shown one at a time, in order. Without a usable terminal
// there is no socket, and popup.Ask answers no.
//
// With a Notifier, a request that doesn't come from a process on this
// terminal - a GUI program inside, or one the guard can't tell - is shown as
// a desktop notification as well, and the first answer of the two counts.
package popuprelay

import (
	"encoding/json/v2"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/mgnsk/sandbox/internal/notify"
	"github.com/mgnsk/sandbox/internal/popup"
)

// Notifier shows a request as a desktop notification: *notify.Notifier.
type Notifier interface {
	Show(req popup.Request) (uint32, error)
	Close(id uint32)
	Events() <-chan notify.Event
}

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
	// How long output the sandbox left behind is waited for after it exits.
	drainQuiet = 50 * time.Millisecond
)

// A notification the daemon takes away sooner than this after it was shown
// isn't shown again: that daemon isn't keeping them.
var minShown = 2 * time.Second

// Usable says whether there's a terminal to relay and show popups on.
func Usable() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
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
	conn net.Conn
	popup.Request
}

func (r request) reply(answer popup.Answer) {
	_, _ = io.WriteString(r.conn, string(answer))
	r.conn.Close()
}

// readRequest reads a guard's request; ok=false if it's malformed.
func readRequest(conn net.Conn) (popup.Request, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, err := io.ReadAll(io.LimitReader(conn, maxRequest+1))
	if err != nil || len(data) > maxRequest {
		return popup.Request{}, false
	}
	var req struct {
		Name    *string `json:"name"`
		Text    *string `json:"text"`
		Session int     `json:"session"`
	}
	if json.Unmarshal(data, &req) != nil || req.Name == nil || req.Text == nil {
		return popup.Request{}, false
	}
	return popup.Request{Name: *req.Name, Text: *req.Text, Session: req.Session}, true
}

// Run runs cmd on a pty of its own, relaying the terminal on stdin and
// stdout, with popups for the guards asking on ln. Signals from signals are
// passed on to cmd, but SIGINT: in raw mode a Ctrl-C reaches the sandbox as
// a key. It returns cmd.Wait's error.
func Run(cmd *exec.Cmd, ln net.Listener, signals <-chan os.Signal) error {
	return run(os.Stdin, os.Stdout, cmd, ln, signals, grace, nil)
}

// RunNotifying is Run, with requests that don't come from this terminal
// shown as notifications by notifier too.
func RunNotifying(cmd *exec.Cmd, ln net.Listener, signals <-chan os.Signal, notifier Notifier) error {
	return run(os.Stdin, os.Stdout, cmd, ln, signals, grace, notifier)
}

// run is Run on the terminal in and out; notifier may be nil.
func run(in, out *os.File, cmd *exec.Cmd, ln net.Listener, signals <-chan os.Signal, grace time.Duration, notifier Notifier) error {
	attrs, err := unix.IoctlGetTermios(int(in.Fd()), unix.TCGETS)
	if err != nil {
		return err
	}
	master, slave, err := pty.Open()
	if err != nil {
		return err
	}
	defer master.Close()
	_ = unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, attrs)
	_ = pty.InheritSize(in, master)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// With the launcher killed there's no one to relay the terminal or
	// answer the guards: the sandbox goes too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Pdeathsig: syscall.SIGTERM}
	err = cmd.Start()
	slave.Close()
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	saved, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		_ = cmd.Process.Kill()
		<-done
		return err
	}
	defer term.Restore(int(in.Fd()), saved) //nolint:errcheck // Nothing left to do about it.

	r := &relay{in: in, out: out, master: master, cmd: cmd, grace: grace, ttyOK: true, modes: modes{cursor: true},
		notifier: notifier}
	return r.loop(ln, signals, done)
}

// relay is the state of a Run: everything here is touched by its loop
// alone.
type relay struct {
	in, out, master *os.File
	cmd             *exec.Cmd
	grace           time.Duration

	ttyOK     bool
	modes     modes
	pending   []byte   // Sandbox output held back under a popup.
	toChild   [][]byte // Keys for the sandbox, not yet written.
	queue     []request
	popup     *pop
	current   request
	screen    bool // The popup screen is open.
	drewOnAlt bool
	resized   bool
	ready     <-chan time.Time // The current popup takes keys.
	unnudge   <-chan time.Time // Size the pty back after a nudge.

	notifier  Notifier  // nil without notifications.
	note      uint32    // The current popup's notification, or 0.
	noteShown time.Time // When it was shown.
}

// reader sends what's read from f, in chunks, until it fails.
func reader(f *os.File, size int) <-chan []byte {
	ch := make(chan []byte)
	go func() {
		defer close(ch)
		for {
			buf := make([]byte, size)
			n, err := f.Read(buf)
			if n > 0 {
				ch <- buf[:n]
			}
			if err != nil {
				return
			}
		}
	}()
	return ch
}

func (r *relay) loop(ln net.Listener, signals <-chan os.Signal, done <-chan error) error {
	input := reader(r.in, 4096)
	output := reader(r.master, 64*1024)
	toMaster := make(chan []byte)
	defer close(toMaster)
	go func() {
		for data := range toMaster {
			_, _ = r.master.Write(data)
		}
	}()
	requests := make(chan request)
	stop := make(chan struct{})
	defer close(stop)
	go accept(ln, requests, stop)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	var notes <-chan notify.Event
	if r.notifier != nil {
		notes = r.notifier.Events()
	}

	for {
		// Not read while the held output is full: the sandbox blocks.
		fromMaster := output
		if len(r.pending) >= maxPending {
			fromMaster = nil
		}
		var write chan<- []byte
		var next []byte
		if len(r.toChild) > 0 {
			write, next = toMaster, r.toChild[0]
		}
		select {
		case data, ok := <-input:
			if !ok {
				input = nil
				r.hangUp()
				continue
			}
			r.onInput(data)
		case data, ok := <-fromMaster:
			if !ok {
				output = nil
				continue
			}
			r.onOutput(data)
		case write <- next:
			r.toChild = r.toChild[1:]
		case req := <-requests:
			r.queue = append(r.queue, req)
			if r.popup == nil {
				r.nextPopup()
			}
		case <-winch:
			r.onResize()
		case event := <-notes:
			r.onNote(event)
		case <-r.ready:
			r.ready = nil
			r.draw()
		case <-r.unnudge:
			r.unnudge = nil
			_ = pty.InheritSize(r.in, r.master)
		case sig := <-signals:
			if sig != syscall.SIGINT {
				_ = r.cmd.Process.Signal(sig)
			}
		case err := <-done:
			r.finish(output)
			return err
		}
	}
}

// accept reads the guards' requests, one at a time, in order, and hands
// them to the loop; once it stops, each is answered no.
func accept(ln net.Listener, requests chan<- request, stop <-chan struct{}) {
	go func() {
		<-stop
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		req, ok := readRequest(conn)
		if !ok {
			conn.Close()
			continue
		}
		select {
		case requests <- request{conn, req}:
		case <-stop:
			request{conn, req}.reply(popup.No)
		}
	}
}

// finish shows what the sandbox wrote before it exited, and answers every
// popup no.
func (r *relay) finish(output <-chan []byte) {
	for quiet := time.After(drainQuiet); output != nil; {
		select {
		case data, ok := <-output:
			if !ok {
				output = nil
				break
			}
			r.onOutput(data)
		case <-quiet:
			output = nil
		}
	}
	if r.popup != nil {
		r.current.reply(popup.No)
		r.popup = nil
		r.closeNote()
	}
	for _, req := range r.queue {
		req.reply(popup.No)
	}
	r.queue = nil
	if r.screen {
		r.closeScreen()
	}
}

// -- the sandbox's side --

func (r *relay) onOutput(data []byte) {
	if r.screen {
		r.pending = append(r.pending, data...)
	} else {
		r.show(data)
	}
}

// show puts sandbox output onto the terminal.
func (r *relay) show(data []byte) {
	r.modes.feed(data)
	r.write(data)
}

// -- the terminal's side --

func (r *relay) write(data []byte) {
	if !r.ttyOK {
		return
	}
	if _, err := r.out.Write(data); err != nil {
		r.ttyOK = false
	}
}

func (r *relay) onInput(data []byte) {
	if r.popup == nil {
		r.toChild = append(r.toChild, data)
		return
	}
	if answer, ok := r.popup.feed(data, time.Now()); ok {
		r.answer(answer)
	} else {
		r.draw()
	}
}

// hangUp: nothing more to relay, and no one to answer popups.
func (r *relay) hangUp() {
	r.ttyOK = false
	if r.popup != nil {
		r.answer(popup.No)
	}
}

func (r *relay) onResize() {
	ws, err := pty.GetsizeFull(r.in)
	if err != nil {
		return
	}
	if !r.screen {
		_ = pty.Setsize(r.master, ws)
		return
	}
	r.resized = true
	if r.popup != nil {
		r.popup.resize(int(ws.Rows), int(ws.Cols))
		r.draw()
	}
}

// -- popups --

func (r *relay) nextPopup() {
	for len(r.queue) > 0 {
		req := r.queue[0]
		r.queue = r.queue[1:]
		if !r.ttyOK {
			req.reply(popup.No)
			continue
		}
		if !r.screen {
			r.openScreen()
		}
		rows, cols := 24, 80
		if ws, err := pty.GetsizeFull(r.in); err == nil {
			rows, cols = int(ws.Rows), int(ws.Cols)
		}
		r.popup = newPop(req.Name, req.Text, rows, cols, time.Now().Add(r.grace))
		r.current = req
		r.ready = time.After(r.grace)
		r.draw()
		if !r.fromHere(req.Request) {
			r.showNote()
		}
		return
	}
	if r.screen {
		r.closeScreen()
	}
}

// fromHere says whether req is for a process on this terminal, whose user
// is looking at it: one of the session the sandbox's pty is the controlling
// terminal of. Anything else - a GUI program inside, a terminal inside one,
// a requester the guard can't tell - isn't.
func (r *relay) fromHere(req popup.Request) bool {
	if req.Session <= 0 {
		return false
	}
	sid, err := unix.IoctlGetInt(int(r.master.Fd()), unix.TIOCGSID)
	return err == nil && sid == req.Session
}

// showNote shows the current popup as a notification too.
func (r *relay) showNote() {
	if r.notifier == nil {
		return
	}
	if id, err := r.notifier.Show(r.current.Request); err == nil {
		r.note, r.noteShown = id, time.Now()
	}
}

func (r *relay) closeNote() {
	if r.note != 0 {
		r.notifier.Close(r.note)
		r.note = 0
	}
}

// onNote handles what happened to a notification: only the current
// popup's counts.
func (r *relay) onNote(event notify.Event) {
	if r.popup == nil || r.note == 0 || event.ID != r.note {
		return
	}
	// The daemon has closed it by now, or will.
	r.note = 0
	early := time.Since(r.noteShown)
	switch event.Kind {
	case notify.Answered:
		// As for keys: a click that was on its way before the notification
		// could be seen doesn't count. Shown again, to be answered.
		if early < r.grace {
			r.showNote()
			return
		}
		r.answer(event.Answer)
	case notify.Dismissed:
		if early < r.grace {
			r.showNote()
			return
		}
		r.answer(popup.No)
	case notify.Gone:
		// Unanswered: still asked on the terminal, and shown again unless
		// the daemon doesn't keep them at all.
		if early >= minShown {
			r.showNote()
		}
	}
}

func (r *relay) answer(answer popup.Answer) {
	r.closeNote()
	r.current.reply(answer)
	r.popup, r.ready = nil, nil
	r.nextPopup()
}

func (r *relay) draw() {
	r.write(r.popup.render(time.Now()))
}

func (r *relay) openScreen() {
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

func (r *relay) closeScreen() {
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
	ws, err := pty.GetsizeFull(r.in)
	switch {
	case err != nil:
	case r.resized:
		_ = pty.Setsize(r.master, ws)
	case r.drewOnAlt:
		// The same size again wouldn't signal; a column less, briefly, has
		// the program inside redraw what the popup covered.
		other := *ws
		if other.Cols > 1 {
			other.Cols--
		} else {
			other.Cols = 2
		}
		_ = pty.Setsize(r.master, &other)
		r.unnudge = time.After(nudge)
	}
}
