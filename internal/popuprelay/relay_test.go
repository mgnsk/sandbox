package popuprelay

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/mgnsk/sandbox/internal/popup"
)

const testGrace = 100 * time.Millisecond

const insideEnv = "POPUPRELAY_TEST_INSIDE"

// TestMain runs the test binary as the sandbox, when the tests start it so.
func TestMain(m *testing.M) {
	if os.Getenv(insideEnv) != "" {
		inside()
		return
	}
	os.Exit(m.Run())
}

// inside is the sandbox: it says its size on each resize, echoes the lines
// it's typed, and does what some of them say.
func inside() {
	winch := make(chan os.Signal, 8)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			if cols, rows, err := term.GetSize(0); err == nil {
				fmt.Printf("size %d %d\n", rows, cols)
			}
		}
	}()
	fmt.Println("ready")
	lines := bufio.NewScanner(os.Stdin)
	for lines.Scan() {
		line := lines.Text()
		switch {
		case line == "quit":
			os.Exit(3)
		case line == "exit-soon":
			time.Sleep(time.Second)
			os.Exit(3)
		case line == "alt":
			fmt.Print("\x1b[?1049h")
		case line == "hide":
			fmt.Print("\x1b[?25l")
		case strings.HasPrefix(line, "later "):
			for _, err := os.Stat(line[len("later "):]); err != nil; _, err = os.Stat(line[len("later "):]) {
				time.Sleep(50 * time.Millisecond)
			}
			fmt.Println("late-output")
		}
		fmt.Println("got:" + line)
	}
}

// session is the launcher on a terminal (the test's pty), with inside
// inside.
type session struct {
	t      *testing.T
	term   *os.File // The user's side of the terminal.
	sock   string
	done   chan error
	mu     sync.Mutex
	output []byte
	mark   int
}

func newSession(t *testing.T) *session {
	term, tty, err := pty.Open()
	if err != nil {
		t.Skip("needs a pty:", err)
	}
	pty.Setsize(term, &pty.Winsize{Rows: 24, Cols: 80})
	s := &session{t: t, term: term, sock: filepath.Join(t.TempDir(), "popup.sock"), done: make(chan error, 1)}
	ln, err := Listen(s.sock)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), insideEnv+"=1")
	signals := make(chan os.Signal)
	go func() { s.done <- run(tty, tty, cmd, ln, signals, testGrace) }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := term.Read(buf)
			s.mu.Lock()
			s.output = append(s.output, buf[:n]...)
			s.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		term.Close()
		tty.Close()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})
	s.expect("ready")
	return s
}

// shown is everything shown since the mark.
func (s *session) shown() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.output[s.mark:])
}

// expect waits for text to show, after what earlier expects saw.
func (s *session) expect(text string) {
	s.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		i := bytes.Index(s.output[s.mark:], []byte(text))
		if i >= 0 {
			s.mark += i + len(text)
		}
		s.mu.Unlock()
		if i >= 0 {
			return
		}
	}
	s.t.Fatalf("%q never shown; got %q", text, s.shown())
}

func (s *session) typeKeys(keys string) { io.WriteString(s.term, keys) }

// answer types keys into the popup once they count.
func (s *session) answer(keys string) {
	time.Sleep(testGrace + 50*time.Millisecond)
	s.typeKeys(keys)
}

// ask asks as a guard does; where the answer lands.
func (s *session) ask(text string) <-chan popup.Answer {
	answer := make(chan popup.Answer, 1)
	go func() { answer <- popup.AskAt(s.sock, popup.Request{Name: "test-guard", Text: text}) }()
	return answer
}

func (s *session) answered(answer <-chan popup.Answer) popup.Answer {
	s.t.Helper()
	select {
	case a := <-answer:
		return a
	case <-time.After(10 * time.Second):
		s.t.Fatal("no answer")
		return ""
	}
}

func (s *session) exit() int {
	s.t.Helper()
	select {
	case err := <-s.done:
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		if err != nil {
			s.t.Fatal(err)
		}
		return 0
	case <-time.After(10 * time.Second):
		s.t.Fatal("still running")
		return -1
	}
}

func TestRelaysBothWaysAndTheExitStatus(t *testing.T) {
	s := newSession(t)
	s.typeKeys("hello\r")
	s.expect("got:hello")
	s.typeKeys("quit\r")
	if code := s.exit(); code != 3 {
		t.Errorf("exit %d", code)
	}
}

func TestResizingReachesTheSandbox(t *testing.T) {
	s := newSession(t)
	pty.Setsize(s.term, &pty.Winsize{Rows: 30, Cols: 100})
	syscall.Kill(os.Getpid(), syscall.SIGWINCH)
	s.expect("size 30 100")
}

func TestThePopupTakesTheKeys(t *testing.T) {
	s := newSession(t)
	answer := s.ask("Allow the thing?")
	s.expect("\x1b[?1049h") // On the alternate screen, over the sandbox's.
	s.expect("Allow the thing?")
	// Within the grace period: dropped, not answered, not relayed.
	s.typeKeys("y\r")
	s.answer("a\r")
	if got := s.answered(answer); got != popup.Always {
		t.Errorf("answer %q", got)
	}
	s.expect("\x1b[?1049l")
	s.typeKeys("after\r")
	s.expect("got:after")
	if out := s.shown(); strings.Contains(out, "got:y") || strings.Contains(out, "got:a") {
		t.Errorf("the sandbox saw the popup's keys: %q", out)
	}
}

func TestPopupsQueueOneAtATime(t *testing.T) {
	s := newSession(t)
	first := s.ask("first request")
	s.expect("first request")
	second := s.ask("second request")
	time.Sleep(200 * time.Millisecond)
	if strings.Contains(s.shown(), "second request") {
		t.Error("second shown over the first")
	}
	s.answer("y\r")
	if got := s.answered(first); got != popup.Once {
		t.Errorf("first: %q", got)
	}
	s.expect("second request")
	s.answer("\r")
	if got := s.answered(second); got != popup.No {
		t.Errorf("second: %q", got)
	}
	s.expect("\x1b[?1049l")
	if strings.Contains(s.shown(), "\x1b[?1049h") {
		t.Error("a screen per popup")
	}
}

func TestOutputIsHeldBackUnderAPopup(t *testing.T) {
	s := newSession(t)
	flag := filepath.Join(t.TempDir(), "flag")
	s.typeKeys("later " + flag + "\r")
	answer := s.ask("question")
	s.expect("question")
	os.WriteFile(flag, nil, 0o600)
	time.Sleep(300 * time.Millisecond)
	if strings.Contains(s.shown(), "late-output") {
		t.Error("output shown under the popup")
	}
	s.answer("y\r")
	s.answered(answer)
	s.expect("late-output")
}

func TestTheSandboxExitingUnderAPopupAnswersNo(t *testing.T) {
	s := newSession(t)
	s.typeKeys("exit-soon\r")
	s.expect("exit-soon") // Echoed.
	answer := s.ask("pending")
	s.expect("pending")
	if got := s.answered(answer); got != popup.No {
		t.Errorf("answer %q", got)
	}
	if code := s.exit(); code != 3 {
		t.Errorf("exit %d", code)
	}
}

func TestHangingUpUnderAPopupAnswersNo(t *testing.T) {
	s := newSession(t)
	answer := s.ask("pending")
	s.expect("pending")
	s.term.Close()
	if got := s.answered(answer); got != popup.No {
		t.Errorf("answer %q", got)
	}
}

func TestMalformedRequestsAreDropped(t *testing.T) {
	s := newSession(t)
	for _, raw := range []string{"not json", "{}", `{"name": "x"}`, `{"name": 1, "text": "x"}`, strings.Repeat("x", maxRequest+1)} {
		conn, err := net.Dial("unix", s.sock)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(conn, raw)
		conn.(*net.UnixConn).CloseWrite()
		if reply, _ := io.ReadAll(conn); len(reply) != 0 {
			t.Errorf("%.20q answered %q", raw, reply)
		}
		conn.Close()
	}
	answer := s.ask("still works")
	s.expect("still works")
	s.answer("y\r")
	if got := s.answered(answer); got != popup.Once {
		t.Errorf("answer %q", got)
	}
}

// On the alternate screen already (vim, less), the popup is drawn there,
// and a resize away and back has the program redraw.
func TestOverAFullScreenProgram(t *testing.T) {
	s := newSession(t)
	s.typeKeys("alt\r")
	s.expect("got:alt")
	answer := s.ask("question")
	s.expect("\x1b7")
	s.expect("question")
	s.answer("y\r")
	s.answered(answer)
	s.expect("\x1b8")
	s.expect("size 24 79")
	s.expect("size 24 80")
}

func TestTheCursorIsLeftAsTheSandboxHadIt(t *testing.T) {
	s := newSession(t)
	s.typeKeys("hide\r")
	s.expect("got:hide")
	answer := s.ask("question")
	s.expect("question")
	s.answer("y\r")
	s.answered(answer)
	s.expect("\x1b[?1049l\x1b[?25l")
}
