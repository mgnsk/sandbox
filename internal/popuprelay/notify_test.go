package popuprelay

import (
	"sync"
	"testing"
	"time"

	"github.com/mgnsk/sandbox/internal/notify"
	"github.com/mgnsk/sandbox/internal/popup"
)

// fakeNotifier records what the relay shows and closes, and lets a test
// answer for the user or the daemon.
type fakeNotifier struct {
	mu     sync.Mutex
	shown  []popup.Request
	closed []uint32
	events chan notify.Event
}

func newFakeNotifier() *fakeNotifier { return &fakeNotifier{events: make(chan notify.Event, 16)} }

func (f *fakeNotifier) Show(req popup.Request) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shown = append(f.shown, req)
	return uint32(len(f.shown)), nil
}

func (f *fakeNotifier) Close(id uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, id)
}

func (f *fakeNotifier) Events() <-chan notify.Event { return f.events }

func (f *fakeNotifier) counts() (shown, closed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.shown), len(f.closed)
}

// waitShown waits until n notifications have been shown.
func (f *fakeNotifier) waitShown(t *testing.T, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if shown, _ := f.counts(); shown >= n {
			return
		}
		if time.Now().After(deadline) {
			shown, _ := f.counts()
			t.Fatalf("%d notifications shown, want %d", shown, n)
		}
	}
}

func (s *session) askFrom(text string, sid int) <-chan popup.Answer {
	answer := make(chan popup.Answer, 1)
	go func() {
		answer <- popup.AskAt(s.sock, popup.Request{Name: "test-guard", Text: text, Session: sid})
	}()
	return answer
}

func afterGrace() { time.Sleep(testGrace + 50*time.Millisecond) }

func TestARequestFromElsewhereIsNotifiedToo(t *testing.T) {
	f := newFakeNotifier()
	s := newSessionWith(t, f)
	answer := s.ask("Allow the thing?")
	s.expect("Allow the thing?") // On the terminal as ever.
	f.waitShown(t, 1)
	if got := f.shown[0]; got.Name != "test-guard" || got.Text != "Allow the thing?" {
		t.Errorf("shown %+v", got)
	}
	// Answered in the notification: the terminal popup goes.
	afterGrace()
	f.events <- notify.Event{ID: 1, Kind: notify.Answered, Answer: popup.Always}
	if got := s.answered(answer); got != popup.Always {
		t.Errorf("answer %q", got)
	}
	s.expect("\x1b[?1049l")
	// The daemon closed it itself.
	if _, closed := f.counts(); closed != 0 {
		t.Errorf("closed %d", closed)
	}
	s.typeKeys("after\r")
	s.expect("got:after")
}

func TestAnsweringOnTheTerminalClosesTheNotification(t *testing.T) {
	f := newFakeNotifier()
	s := newSessionWith(t, f)
	answer := s.ask("Allow?")
	s.expect("Allow?")
	f.waitShown(t, 1)
	s.answer("y\r")
	if got := s.answered(answer); got != popup.Once {
		t.Errorf("answer %q", got)
	}
	s.expect("\x1b[?1049l")
	if _, closed := f.counts(); closed != 1 || f.closed[0] != 1 {
		t.Errorf("closed %v", f.closed)
	}
	// A click that comes after counts for nothing.
	f.events <- notify.Event{ID: 1, Kind: notify.Answered, Answer: popup.Always}
	next := s.ask("Next?")
	s.expect("Next?")
	f.waitShown(t, 2)
	s.answer("\r")
	if got := s.answered(next); got != popup.No {
		t.Errorf("answer %q", got)
	}
}

func TestARequestFromThisTerminalIsNotNotified(t *testing.T) {
	f := newFakeNotifier()
	s := newSessionWith(t, f)
	// The sandbox leads the session of its pty.
	answer := s.askFrom("From the shell?", s.cmd.Process.Pid)
	s.expect("From the shell?")
	s.answer("y\r")
	if got := s.answered(answer); got != popup.Once {
		t.Errorf("answer %q", got)
	}
	// Another session's is.
	other := s.askFrom("From a window?", s.cmd.Process.Pid+1)
	s.expect("From a window?")
	f.waitShown(t, 1)
	if shown, _ := f.counts(); shown != 1 || f.shown[0].Text != "From a window?" {
		t.Errorf("shown %+v", f.shown)
	}
	s.answer("\r")
	s.answered(other)
}

func TestNotificationAnswersWithinTheGraceAreDropped(t *testing.T) {
	f := newFakeNotifier()
	s := newSessionWith(t, f)
	answer := s.ask("Allow?")
	s.expect("Allow?")
	f.waitShown(t, 1)
	// A click on its way before it could be seen: asked again.
	f.events <- notify.Event{ID: 1, Kind: notify.Answered, Answer: popup.Always}
	f.waitShown(t, 2)
	select {
	case got := <-answer:
		t.Fatalf("answered %q", got)
	case <-time.After(50 * time.Millisecond):
	}
	// Another sandbox's notification isn't this one's.
	afterGrace()
	f.events <- notify.Event{ID: 77, Kind: notify.Answered, Answer: popup.Always}
	f.events <- notify.Event{ID: 2, Kind: notify.Dismissed}
	if got := s.answered(answer); got != popup.No {
		t.Errorf("answer %q", got)
	}
}

func TestANotificationTheDaemonTakesAwayIsShownAgain(t *testing.T) {
	saved := minShown
	minShown = 3 * testGrace
	t.Cleanup(func() { minShown = saved })
	f := newFakeNotifier()
	s := newSessionWith(t, f)
	answer := s.ask("Allow?")
	s.expect("Allow?")
	f.waitShown(t, 1)
	time.Sleep(minShown + 20*time.Millisecond)
	f.events <- notify.Event{ID: 1, Kind: notify.Gone}
	f.waitShown(t, 2)
	// Taken away at once: that daemon keeps none, and it's left at that.
	f.events <- notify.Event{ID: 2, Kind: notify.Gone}
	time.Sleep(50 * time.Millisecond)
	if shown, _ := f.counts(); shown != 2 {
		t.Errorf("shown %d times", shown)
	}
	// Still asked on the terminal.
	s.answer("a\r")
	if got := s.answered(answer); got != popup.Always {
		t.Errorf("answer %q", got)
	}
	if _, closed := f.counts(); closed != 0 {
		t.Errorf("closed %v", f.closed)
	}
}

func TestTheSandboxExitingClosesTheNotification(t *testing.T) {
	f := newFakeNotifier()
	s := newSessionWith(t, f)
	s.typeKeys("exit-soon\r")
	s.expect("exit-soon")
	answer := s.ask("pending")
	s.expect("pending")
	if got := s.answered(answer); got != popup.No {
		t.Errorf("answer %q", got)
	}
	s.exit()
	if shown, closed := f.counts(); shown != 1 || closed != 1 {
		t.Errorf("shown %d, closed %d", shown, closed)
	}
}
