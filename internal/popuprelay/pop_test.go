package popuprelay

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mgnsk/sandbox/internal/popup"
)

func TestWrap(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []string
	}{
		{strings.Repeat("x", 25), []string{strings.Repeat("x", 10), strings.Repeat("x", 10), "xxxxx"}},
		// Anything past ASCII counts double, wide or not.
		{strings.Repeat("界", 7), []string{"界界界界界", "界界"}},
		// Escapes, bidi overrides and carriage returns become "?"; tabs
		// four spaces.
		{"a\x1b[2Jb\u202ec\rd\tz", []string{"a?[2Jb?c?d", "    z"}},
		// Trailing blank lines go.
		{"a\n\nb\n\n\n", []string{"a", "", "b"}},
	} {
		if got := wrap(tc.text, 10); !slices.Equal(got, tc.want) {
			t.Errorf("wrap(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
	if got := fit("界界x", 4); got != "界界" {
		t.Errorf("fit = %q", got)
	}
	if got := fit("ab", 4); got != "ab  " {
		t.Errorf("fit = %q", got)
	}
}

func TestFeed(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		keys string
		want popup.Answer
	}{
		{"y\r", popup.Once},
		{"Y\r", popup.Once},
		{"y\n", popup.Once},
		{"a\r", popup.Always},
		{"A\r", popup.Always},
		{"\r", popup.No},
		{"n\r", popup.No},
		{"yes\r", popup.No},
		{"\x03", popup.No},
		{"\x04", popup.No},
		{"x\x7fy\r", popup.Once},
		{"x\by\r", popup.Once},
		{"a\x15\r", popup.No},
		{"\x1b[Ay\r", popup.Once}, // Scrolling never types.
		{"d\r", popup.Never},
		{"D\r", popup.Never},
		// What a terminal answers a query of the sandbox's with - its
		// title, a color, a setting - is no key, however it ends.
		{"\x1b]ly\x1b\\\r", popup.No},
		{"\x1b]11;rgb:0000/0000/0000\ay\r", popup.Once},
		{"\x1bP1$ry\x1b\\a\r", popup.Always},
		{"\x1b_Gi=1;y\x1b\\\r", popup.No},
		{"n\x1b]0;y", ""}, // Unterminated: all of it.
	} {
		if tc.want == "" {
			p := newPop("g", "text", 24, 80, now)
			if _, ok := p.feed([]byte(tc.keys), now); ok || p.typed != "n" {
				t.Errorf("%q: typed %q", tc.keys, p.typed)
			}
			continue
		}
		p := newPop("g", "text", 24, 80, now)
		if got, ok := p.feed([]byte(tc.keys), now); !ok || got != tc.want {
			t.Errorf("%q: %q, %v", tc.keys, got, ok)
		}
	}
	// Keys during the grace period are dropped.
	p := newPop("g", "text", 24, 80, now.Add(time.Second))
	if _, ok := p.feed([]byte("y\r"), now); ok {
		t.Error("answered during the grace period")
	}
	// No answer until Enter.
	p = newPop("g", "text", 24, 80, now)
	if _, ok := p.feed([]byte("y"), now); ok || !strings.Contains(string(p.render(now)), prompt+"y") {
		t.Error("answered without Enter, or not shown")
	}
}

func TestScroll(t *testing.T) {
	var lines []string
	for i := range 30 {
		lines = append(lines, "line"+string(rune('a'+i)))
	}
	now := time.Now()
	p := newPop("g", strings.Join(lines, "\n"), 24, 80, now)
	shown := func() string { return string(p.render(now)) }
	if !strings.Contains(shown(), "lines 1-21 of 30 - Up/Down/PgUp/PgDn to read it all") || strings.Contains(shown(), lines[21]) {
		t.Fatalf("first page: %q", shown())
	}
	for keys, want := range map[string]string{
		"\x1b[B\x1b[B\x1bOB": "lines 4-24 of 30",
		"\x1b[6~\x1b[6~":     "lines 10-30 of 30",
		"\x1b[H":             "lines 1-21 of 30",
		"\x1b[F":             "lines 10-30 of 30",
		"\x1b[5~\x1b[A":      "lines 1-21 of 30",
	} {
		p.top = 0
		if keys == "\x1b[5~\x1b[A" || keys == "\x1b[H" {
			p.top = p.maxTop()
		}
		p.feed([]byte(keys), now)
		if !strings.Contains(shown(), want) {
			t.Errorf("%q: %q", keys, shown())
		}
	}
	// Resized taller, everything fits.
	p.resize(40, 80)
	if strings.Contains(shown(), "lines ") || !strings.Contains(shown(), lines[29]) {
		t.Errorf("after resize: %q", shown())
	}
}

func TestRender(t *testing.T) {
	now := time.Now()
	p := newPop("evil\x1b[31m", "Open?\n\n  host:     example.com", 24, 80, now.Add(time.Second))
	screen := string(p.render(now))
	for _, want := range []string{
		" sandbox: evil?[31m asks for approval",
		"\x1b[2;1HOpen?",
		"\x1b[4;1H  host:     example.com",
		"\x1b[24;1H\x1b[2m" + strings.TrimSpace(prompt), // Dim until keys count.
	} {
		if !strings.Contains(screen, want) {
			t.Errorf("%q not in %q", want, screen)
		}
	}
	if strings.Contains(screen, "\x1b[31m") {
		t.Error("an escape from the request drawn")
	}
}

func TestModes(t *testing.T) {
	var m modes
	m.cursor = true
	m.feed([]byte("text\x1b[?1049h"))
	if !m.alt {
		t.Error("alt screen not seen")
	}
	// Split across two reads.
	m.feed([]byte("\x1b[?10"))
	m.feed([]byte("49l\x1b[?25l"))
	if m.alt || m.cursor {
		t.Errorf("split: %+v", m)
	}
	m.feed([]byte("\x1b[?1047;25h"))
	if !m.alt || !m.cursor {
		t.Errorf("both at once: %+v", m)
	}
	// A terminal reset brings back the main screen and the cursor.
	m.feed([]byte("\x1b[?25l\x1bc"))
	if m.alt || !m.cursor {
		t.Errorf("reset: %+v", m)
	}
	// Other sequences are passed over.
	m.feed([]byte("\x1b[31m\x1b]52;c;aGk=\x07\x1b[?2004h"))
	if m.alt || !m.cursor {
		t.Errorf("others: %+v", m)
	}
}
