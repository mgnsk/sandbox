package popuprelay

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mgnsk/sandbox/internal/popup"
)

const prompt = "y = once, A = always in this sandbox, N = no, D = never: "

// sanitize turns anything non-printable (escape sequences, bidi overrides,
// line separators) into "?": popup text is drawn on the terminal as is.
func sanitize(s string) string {
	return popup.Clean(strings.ReplaceAll(s, "\t", "    "))
}

// width is how many columns r takes, at most: two for anything outside
// ASCII, which may be wide. Overcounting only wraps a line early, where
// undercounting would let it run past the edge, under the prompt.
func width(r rune) int {
	if r < utf8.RuneSelf {
		return 1
	}
	return 2
}

// fit cuts s to cols columns, and pads it to them.
func fit(s string, cols int) string {
	var b strings.Builder
	used := 0
	for _, r := range s {
		if used+width(r) > cols {
			break
		}
		b.WriteRune(r)
		used += width(r)
	}
	b.WriteString(strings.Repeat(" ", cols-used))
	return b.String()
}

// wrap gives the lines of text, sanitized and hard-wrapped at cols
// columns - not cut: a request is approved for exactly what's shown.
func wrap(text string, cols int) []string {
	var lines []string
	for raw := range strings.SplitSeq(text, "\n") {
		var line strings.Builder
		used := 0
		for _, r := range sanitize(raw) {
			if used+width(r) > cols && line.Len() > 0 {
				lines = append(lines, line.String())
				line.Reset()
				used = 0
			}
			line.WriteRune(r)
			used += width(r)
		}
		lines = append(lines, line.String())
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// nextKey splits the first key off data: a CSI or SS3 escape sequence, a
// control string, or one byte.
func nextKey(data []byte) (key string, rest []byte) {
	// A control string (OSC, DCS, APC, PM, SOS), up to its terminator, or
	// all there is: what a terminal answers a query with - its title, its
	// colors - which the sandbox may have asked for just before the popup.
	// Its text is no key.
	if len(data) >= 2 && data[0] == '\x1b' && strings.IndexByte("]P_^X", data[1]) >= 0 {
		for i := 2; i < len(data); i++ {
			switch {
			case data[i] == '\a':
				return string(data[:i+1]), data[i+1:]
			case data[i] == '\\' && data[i-1] == '\x1b':
				return string(data[:i+1]), data[i+1:]
			}
		}
		return string(data), nil
	}
	if len(data) >= 3 && data[0] == '\x1b' {
		switch data[1] {
		case '[':
			// Parameter bytes, intermediate bytes, a final byte (ECMA-48).
			i := 2
			for i < len(data) && data[i] >= 0x30 && data[i] <= 0x3f {
				i++
			}
			for i < len(data) && data[i] >= 0x20 && data[i] <= 0x2f {
				i++
			}
			if i < len(data) && data[i] >= 0x40 && data[i] <= 0x7e {
				return string(data[:i+1]), data[i+1:]
			}
		case 'O':
			return string(data[:3]), data[3:]
		}
	}
	return string(data[:1]), data[1:]
}

// pop is one request on screen: the text, scrollable, and a y/A/N prompt
// read as a line like `read` would (Enter alone is no).
type pop struct {
	name, text string
	readyAt    time.Time
	typed      string
	top        int
	rows, cols int
	lines      []string
}

func newPop(name, text string, rows, cols int, readyAt time.Time) *pop {
	p := &pop{name: sanitize(name), text: text, readyAt: readyAt}
	p.resize(rows, cols)
	return p
}

func (p *pop) resize(rows, cols int) {
	p.rows, p.cols = max(rows, 4), max(cols, 10)
	p.lines = wrap(p.text, p.cols)
	p.top = min(p.top, p.maxTop())
}

func (p *pop) bodyRows() int { return p.rows - 3 }

func (p *pop) maxTop() int { return max(len(p.lines)-p.bodyRows(), 0) }

func (p *pop) scroll(by int) { p.top = min(max(p.top+by, 0), p.maxTop()) }

// feed handles typed bytes; ok once there's an answer.
func (p *pop) feed(data []byte, now time.Time) (answer popup.Answer, ok bool) {
	if now.Before(p.readyAt) {
		return "", false
	}
	for len(data) > 0 {
		var key string
		key, data = nextKey(data)
		switch key {
		case "\r", "\n":
			switch strings.ToLower(p.typed) {
			case "y":
				return popup.Once, true
			case "a":
				return popup.Always, true
			case "d":
				return popup.Never, true
			}
			return popup.No, true
		case "\x03", "\x04": // Ctrl-C, Ctrl-D.
			return popup.No, true
		case "\x7f", "\b":
			if p.typed != "" {
				p.typed = p.typed[:len(p.typed)-1]
			}
		case "\x15": // Ctrl-U.
			p.typed = ""
		case "\x1b[A", "\x1bOA":
			p.scroll(-1)
		case "\x1b[B", "\x1bOB":
			p.scroll(1)
		case "\x1b[5~":
			p.scroll(-p.bodyRows())
		case "\x1b[6~":
			p.scroll(p.bodyRows())
		case "\x1b[H", "\x1bOH", "\x1b[1~":
			p.top = 0
		case "\x1b[F", "\x1bOF", "\x1b[4~":
			p.top = p.maxTop()
		default:
			if r := rune(key[0]); len(key) == 1 && r < utf8.RuneSelf && unicode.IsPrint(r) && len(p.typed) < 16 {
				p.typed += key
			}
		}
	}
	return "", false
}

// render is the whole screen, as bytes for the terminal.
func (p *pop) render(now time.Time) []byte {
	var b bytes.Buffer
	b.WriteString("\x1b[0m\x1b(B\x1b[?25l\x1b[H\x1b[2J")
	at := func(row int, s string) { fmt.Fprintf(&b, "\x1b[%d;1H%s", row, s) }

	at(1, "\x1b[7m"+fit(" sandbox: "+p.name+" asks for approval", p.cols)+"\x1b[0m")
	body := p.lines[p.top:min(p.top+p.bodyRows(), len(p.lines))]
	for i, line := range body {
		at(2+i, line)
	}
	if p.maxTop() > 0 {
		status := fmt.Sprintf(" lines %d-%d of %d - Up/Down/PgUp/PgDn to read it all",
			p.top+1, p.top+len(body), len(p.lines))
		at(p.rows-1, "\x1b[7m"+fit(status, p.cols)+"\x1b[0m")
	}
	line := strings.TrimRightFunc(fit(prompt+p.typed, p.cols-1), unicode.IsSpace)
	if now.Before(p.readyAt) {
		at(p.rows, "\x1b[2m"+line+"\x1b[0m")
	} else {
		at(p.rows, line+"\x1b[?25h")
	}
	return b.Bytes()
}

// modes are the few terminal modes of the sandbox's that a popup has to
// restore, tracked from its output.
type modes struct {
	alt, cursor bool
	// An escape sequence cut off at the end of the last output, completed
	// by the next.
	partial []byte
}

func (m *modes) feed(data []byte) {
	buf := append(m.partial, data...)
	m.partial = nil
	for {
		i := bytes.IndexByte(buf, '\x1b')
		if i < 0 {
			return
		}
		buf = buf[i:]
		n, complete := m.sequence(buf)
		if !complete {
			if len(buf) <= 32 {
				m.partial = bytes.Clone(buf)
			}
			return
		}
		buf = buf[n:]
	}
}

// sequence applies the escape sequence at the start of buf - RIS (\ec), or
// DEC private modes set or reset (\e[?Pm h/l) - and returns its length, or
// complete=false if buf ends inside one.
func (m *modes) sequence(buf []byte) (n int, complete bool) {
	switch {
	case len(buf) < 2:
		return 0, false
	case buf[1] == 'c':
		m.alt, m.cursor = false, true
		return 2, true
	case buf[1] != '[':
		return 1, true
	case len(buf) < 3:
		return 0, false
	case buf[2] != '?':
		return 1, true
	}
	end := bytes.IndexFunc(buf[3:], func(r rune) bool { return !unicode.IsDigit(r) && r != ';' })
	if end < 0 {
		return 0, false
	}
	end += 3
	if final := buf[end]; final == 'h' || final == 'l' {
		for mode := range strings.SplitSeq(string(buf[3:end]), ";") {
			switch mode {
			case "1049", "1047", "47":
				m.alt = final == 'h'
			case "25":
				m.cursor = final == 'h'
			}
		}
	}
	return end + 1, true
}
