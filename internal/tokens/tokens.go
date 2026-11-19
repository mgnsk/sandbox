// Package tokens checks tokens, and keeps the Claude API key a project
// keeps outside its sandbox: a file in the project's volume dir, which the
// launcher writes (`sandbox --claude-api-key`) and claude-api-proxy reads
// per request, so a key set later reaches running sandboxes. (The GitHub
// and Forgejo tokens are never on disk: token commands print them at
// start.)
package tokens

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
)

// ClaudeFile is the Claude API key's file, in a project's volume dir.
const ClaudeFile = "claude-api-key"

// Valid says whether token can be one: 8 to 1024 printable ASCII
// characters, no spaces - so it can't smuggle a header into a request.
func Valid(token string) bool {
	return len(token) >= 8 && len(token) <= 1024 && !strings.ContainsFunc(token, func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r)
	})
}

// Read is the token in the file at path, or "" if it's missing or not
// Valid.
func Read(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if token := strings.TrimSpace(string(data)); Valid(token) {
		return token
	}
	return ""
}

// Write replaces the token file at path.
func Write(path, token string) error {
	if !Valid(token) {
		return errors.New("not a valid token")
	}
	return writeFile(path, []byte(token+"\n"))
}

// writeFile replaces the file at path (in a volume dir, never in the home
// volume the sandbox writes) with data, readable only by the user.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
