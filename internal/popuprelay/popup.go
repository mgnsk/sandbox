package popuprelay

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/width"
)

const prompt = "y = once, A = always in this sandbox, N = no: "

// sanitize turns anything non-printable (escape sequences, bidi overrides,
// line separators) into "?": popup text is drawn on the terminal as is.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, strings.ReplaceAll(s, "\t", "    "))
}

func charWidth(r rune) int {
	if norm.NFD.PropertiesString(string(r)).CCC() != 0 {
		return 0
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	return 1
}

// fit cuts s to width columns, and pads it to them.
func fit(s string, cols int) string {
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := charWidth(r)
		if used+w > cols {
			break
		}
		b.WriteRune(r)
		used += w
	}
	if cols > used {
		b.WriteString(strings.Repeat(" ", cols-used))
	}
	return b.String()
}

// wrap gives the lines of text, sanitized and hard-wrapped at width
// columns - not cut: a request is approved for exactly what's shown.
func wrap(text string, cols int) []string {
	var lines []string
	for _, raw := range strings.Split(text, "\n") {
		var line strings.Builder
		used := 0
		for _, r := range sanitize(raw) {
			w := charWidth(r)
			if used+w > cols && line.Len() > 0 {
				lines = append(lines, line.String())
				line.Reset()
				used = 0
			}
			line.WriteRune(r)
			used += w
		}
		lines = append(lines, line.String())
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

var keyRE = regexp.MustCompile(`(?s)\x1b\[[0-?]*[ -/]*[@-~]|\x1bO.|.`)

func isOneOf(key string, keys ...string) bool {
	for _, k := range keys {
		if key == k {
			return true
		}
	}
	return false
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

func newPop(name, text string, rows, cols int, now time.Time, grace time.Duration) *pop {
	p := &pop{name: sanitize(name), text: text, readyAt: now.Add(grace)}
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

// feed handles typed bytes; the answer ("once", "always", "no") once there
// is one, else "".
func (p *pop) feed(data []byte, now time.Time) string {
	if now.Before(p.readyAt) {
		return ""
	}
	// The regexp works on bytes as Latin-1 would be: one key per byte
	// outside a sequence, whatever the encoding.
	for _, m := range keyRE.FindAll(latin1(data), -1) {
		key := fromLatin1(m)
		switch {
		case key == "\r" || key == "\n":
			switch strings.ToLower(p.typed) {
			case "y":
				return "once"
			case "a":
				return "always"
			}
			return "no"
		case key == "\x03" || key == "\x04":
			return "no"
		case key == "\x7f" || key == "\x08":
			if p.typed != "" {
				p.typed = p.typed[:len(p.typed)-1]
			}
		case key == "\x15":
			p.typed = ""
		case isOneOf(key, "\x1b[A", "\x1bOA"):
			p.scroll(-1)
		case isOneOf(key, "\x1b[B", "\x1bOB"):
			p.scroll(1)
		case key == "\x1b[5~":
			p.scroll(-p.bodyRows())
		case key == "\x1b[6~":
			p.scroll(p.bodyRows())
		case isOneOf(key, "\x1b[H", "\x1bOH", "\x1b[1~"):
			p.top = 0
		case isOneOf(key, "\x1b[F", "\x1bOF", "\x1b[4~"):
			p.top = p.maxTop()
		case len(key) == 1 && key[0] >= 0x20 && key[0] < 0x7f && len(p.typed) < 16:
			p.typed += key
		}
	}
	return ""
}

// latin1 maps each byte to a rune, so the regexp's "." takes one byte.
func latin1(data []byte) []byte {
	var b strings.Builder
	for _, c := range data {
		b.WriteRune(rune(c))
	}
	return []byte(b.String())
}

func fromLatin1(m []byte) string {
	var out []byte
	for _, r := range string(m) {
		out = append(out, byte(r))
	}
	return string(out)
}

// render is the whole screen, as bytes for the terminal.
func (p *pop) render(now time.Time) []byte {
	var b strings.Builder
	b.WriteString("\x1b[0m\x1b(B\x1b[?25l\x1b[H\x1b[2J")
	at := func(row int, s string) { fmt.Fprintf(&b, "\x1b[%d;1H%s", row, s) }

	title := " sandbox: " + p.name + " asks for approval"
	at(1, "\x1b[7m"+fit(title, p.cols)+"\x1b[0m")
	end := min(p.top+p.bodyRows(), len(p.lines))
	body := p.lines[p.top:end]
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
	return []byte(b.String())
}

// modes are the few terminal modes of the sandbox's that a popup has to
// restore, tracked from its output.
type modes struct {
	alt, cursor bool
	tail        []byte
}

var modeRE = regexp.MustCompile(`\x1b\[\?([0-9;]*)([hl])|\x1bc`)

func (m *modes) feed(data []byte) {
	// The tail of the last chunk again, for a sequence split across two:
	// matched twice, but in order, so the last one still wins.
	buf := append(append([]byte{}, m.tail...), data...)
	for _, sub := range modeRE.FindAllSubmatch(buf, -1) {
		if string(sub[0]) == "\x1bc" {
			m.alt, m.cursor = false, true
			continue
		}
		on := string(sub[2]) == "h"
		for _, mode := range strings.Split(string(sub[1]), ";") {
			switch mode {
			case "1049", "1047", "47":
				m.alt = on
			case "25":
				m.cursor = on
			}
		}
	}
	if len(buf) > 32 {
		buf = buf[len(buf)-32:]
	}
	m.tail = buf
}
