package apiproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// The HTTP/1.1 a client speaks to a guard, read here rather than by
// net/http: one request per connection, refused with the guard's own
// messages for anything this proxy and upstream might read differently
// (two Host headers, two Content-Lengths, a chunked body), and passed on
// with its headers as sent - names, case and order.

const (
	maxLine    = 65536
	maxHeaders = 100
	chunk      = 64 * 1024
)

// header is one request header as the client sent it. Names and values
// are bytes - Latin-1, as HTTP has it - not necessarily UTF-8.
type header struct{ name, value string }

type request struct {
	method, path, version string
	headers               []header
}

// all returns every value of the header name (case-insensitive).
func (r *request) all(name string) []string {
	var out []string
	for _, h := range r.headers {
		if asciiLower(h.name) == name {
			out = append(out, h.value)
		}
	}
	return out
}

func (r *request) has(name string) bool { return len(r.all(name)) > 0 }

// httpError is a request this proxy can't read; refused with its status.
type httpError struct {
	status  int
	message string
}

var errTooLong = errors.New("line too long")

// readLine reads a line of at most max bytes, without its line ending; ""
// with io.EOF at the end of the stream.
func readLine(br *bufio.Reader, max int) (string, error) {
	var line []byte
	for {
		part, err := br.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > max {
			return "", errTooLong
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && len(line) == 0 {
			return "", err
		}
		return strings.TrimRight(string(line), "\r\n"), nil
	}
}

// Python's str.split() whitespace, over Latin-1.
func isPySpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0:
		return true
	}
	return false
}

func pyFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if isPySpace(s[i]) {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func pyStrip(s string) string {
	i, j := 0, len(s)
	for i < j && isPySpace(s[i]) {
		i++
	}
	for j > i && isPySpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x21 || c > 0x7e || c == ':' {
			return false
		}
	}
	return true
}

// readRequest reads a request line and headers. A nil request and nil
// error mean the client sent nothing.
func readRequest(br *bufio.Reader) (*request, *httpError) {
	line, err := readLine(br, maxLine)
	if errors.Is(err, errTooLong) {
		return nil, &httpError{http.StatusRequestURITooLong, "request line too long"}
	}
	if err != nil {
		return nil, nil
	}
	words := pyFields(line)
	if len(words) == 0 {
		return nil, nil
	}
	if len(words) != 3 {
		return nil, &httpError{http.StatusBadRequest, "bad request syntax"}
	}
	r := &request{method: words[0], path: words[1], version: words[2]}
	base, ok := strings.CutPrefix(r.version, "HTTP/")
	major, minor, ok2 := strings.Cut(base, ".")
	if !ok || !ok2 || !isDigits(major) || !isDigits(minor) || len(major) > 10 || len(minor) > 10 {
		return nil, &httpError{http.StatusBadRequest, "bad request version"}
	}
	if strings.TrimLeft(major, "0") != "" && strings.TrimLeft(major, "0") != "1" {
		return nil, &httpError{http.StatusHTTPVersionNotSupported, "invalid HTTP version"}
	}
	// As http.server: a target of //x is /x, never a network-path reference.
	if strings.HasPrefix(r.path, "//") {
		r.path = "/" + strings.TrimLeft(r.path, "/")
	}
	// At most maxHeaders lines, the blank one included, as http.client.
	for n := 1; ; n++ {
		line, err := readLine(br, maxLine)
		if errors.Is(err, errTooLong) {
			return nil, &httpError{http.StatusRequestHeaderFieldsTooLarge, "header line too long"}
		}
		if n > maxHeaders {
			return nil, &httpError{http.StatusRequestHeaderFieldsTooLarge, "too many headers"}
		}
		if err != nil || line == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found || !validName(name) {
			// Obsolete line folding included: refused, not unfolded.
			return nil, &httpError{http.StatusBadRequest, "malformed header"}
		}
		r.headers = append(r.headers, header{name, strings.TrimLeft(value, " \t")})
	}
	return r, nil
}

// clean replaces non-printable characters (e.g. terminal escapes) with "?"
// for safe display, keeping line breaks. Never truncates: a write is
// approved for exactly what's shown.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}

// latin1 reads s (bytes off the wire) as Latin-1, as http.server does.
func latin1(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteRune(rune(s[i]))
	}
	return b.String()
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// refuse answers with an error the client shows as its message.
func refuse(w io.Writer, name string, status int, message string, extra ...header) {
	body, _ := json.Marshal(map[string]string{"message": name + ": " + message})
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	b.WriteString("Content-Type: application/json; charset=utf-8\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("Connection: close\r\n")
	for _, h := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", h.name, h.value)
	}
	b.WriteString("\r\n")
	b.Write(body)
	_, _ = w.Write(b.Bytes())
}

// timeoutConn gives each read and write its own deadline, as a socket
// timeout does.
type timeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *timeoutConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(p)
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}

// closeWrite half-closes conn when it can, through the wrappers here.
func closeWrite(conn net.Conn) {
	for {
		switch c := conn.(type) {
		case *timeoutConn:
			conn = c.Conn
			continue
		case *bufConn:
			conn = c.Conn
			continue
		case interface{ CloseWrite() error }:
			_ = c.CloseWrite()
		}
		return
	}
}
