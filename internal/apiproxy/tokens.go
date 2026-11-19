package apiproxy

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

var tokenChars = regexp.MustCompile(`^[A-Za-z0-9_.~+/=-]+$`)

// ValidToken says whether token is what `sandbox --gh-token` / `--fj-token`
// accept: 8 to 1024 characters, no whitespace or control characters, so a
// token can't smuggle a header into a request.
func ValidToken(token string) bool {
	return len(token) >= 8 && len(token) <= 1024 && tokenChars.MatchString(token)
}

// readText reads a small UTF-8 text file, stripped of surrounding space.
func readText(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// ReadToken is the project token in the file at path (written by the
// launcher, out of the sandbox's reach), or "" if it's missing or
// malformed. Read per request, so setting one reaches running sandboxes.
func ReadToken(path string) string {
	token, ok := readText(path)
	if !ok || !ValidToken(token) {
		return ""
	}
	return token
}

// ReadTokens is {host: token} from the JSON file at path, keeping only
// well-formed entries; empty if it's missing or unreadable.
func ReadTokens(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return out
	}
	for host, v := range raw {
		if token, ok := v.(string); ok && ValidToken(token) {
			out[strings.ToLower(host)] = token
		}
	}
	return out
}

// URLPath is a request target's path, without its query or fragment, as
// Python's urlsplit took it: trailing control characters and spaces
// dropped too.
func URLPath(target string) string {
	target = strings.TrimRightFunc(target, func(r rune) bool { return r <= ' ' })
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	return target
}
