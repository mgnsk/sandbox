// Package tokens holds the credentials a project keeps outside its sandbox:
// files in the project's volume dir, which the launcher writes (`sandbox
// --gh-token` and the like) and the API guards read per request, so a token
// set later reaches running sandboxes.
package tokens

import (
	"encoding/json/v2"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/mgnsk/sandbox/internal/hostname"
)

// The files, in a project's volume dir.
const (
	GitHubFile  = "github-token"        // The GitHub token.
	ForgejoFile = "forgejo-tokens.json" // {host: token} for Forgejo instances.
	ClaudeFile  = "claude-api-key"      // The Claude API key.
)

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

// ReadHosts is the {host: token} file at path, keeping only Valid tokens
// for valid hosts; empty if it's missing or unreadable.
func ReadHosts(path string) map[string]string {
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
		host, ok := hostname.Normalize(host)
		if token, isString := v.(string); ok && isString && Valid(token) {
			out[host] = token
		}
	}
	return out
}

// Write replaces the token file at path.
func Write(path, token string) error {
	if !Valid(token) {
		return errors.New("not a valid token")
	}
	return writeFile(path, []byte(token+"\n"))
}

// WriteHost sets host's token in the {host: token} file at path, replacing
// a file that isn't one.
func WriteHost(path, host, token string) error {
	if !Valid(token) {
		return errors.New("not a valid token")
	}
	tokens := map[string]string{}
	if data, err := os.ReadFile(path); err == nil {
		var existing map[string]string
		if json.Unmarshal(data, &existing) == nil {
			maps.Copy(tokens, existing)
		}
	}
	tokens[host] = token
	data, err := json.Marshal(tokens, json.Deterministic(true))
	if err != nil {
		return err
	}
	return writeFile(path, append(data, '\n'))
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
