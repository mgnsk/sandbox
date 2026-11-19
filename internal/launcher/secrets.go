package launcher

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/mgnsk/sandbox/internal/tokens"
)

// tty is the controlling terminal, also when stdin and stdout are
// redirected.
type tty struct {
	*os.File
	r *bufio.Reader
}

func openTTY() (*tty, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	return &tty{File: f, r: bufio.NewReaderSize(f, 1)}, nil
}

func (t *tty) readLine() string {
	line, _ := t.r.ReadString('\n')
	return strings.TrimSpace(line)
}

// confirm asks a yes/no question, no being the default.
func (t *tty) confirm(question string) bool {
	_, _ = io.WriteString(t, question)
	switch strings.ToLower(t.readLine()) {
	case "y", "yes":
		return true
	}
	return false
}

// readSecret reads a line from the terminal without echoing it.
func (t *tty) readSecret(prompt string) string {
	_, _ = io.WriteString(t, prompt)
	secret, err := term.ReadPassword(int(t.Fd()))
	_, _ = io.WriteString(t, "\n")
	if err != nil {
		return t.readLine()
	}
	return strings.TrimSpace(string(secret))
}

// askToken reads a token on the terminal (hidden input); "" when skipped
// or malformed.
func askToken(intro, prompt string) (string, error) {
	if os.Getenv("SANDBOX_EXCHANGE") != "" {
		// Only a hint, not a control: in here it would land in this
		// sandbox's volume, where no proxy reads it.
		return "", errors.New("this is inside a sandbox - set the token on the host, in the project")
	}
	t, err := openTTY()
	if err != nil {
		return "", errors.New("setting a token needs a terminal - run it in one on the host, in the project")
	}
	defer t.Close()
	_, _ = io.WriteString(t, intro)
	token := t.readSecret(prompt)
	switch {
	case token == "":
		_, _ = io.WriteString(t, "sandbox: nothing changed\n")
	case !tokens.Valid(token):
		_, _ = io.WriteString(t, "sandbox: that doesn't look like a token, not saved\n")
		token = ""
	}
	return token, nil
}

// claudeAPIKey asks for the project's Claude API key on the terminal when
// there's none yet (or askAgain). It's kept in the volume dir, out of the
// sandbox's reach; claude-api-proxy reads it per request, so a key set
// later reaches a running sandbox.
func claudeAPIKey(volumeDir string, askAgain bool) error {
	keyFile := filepath.Join(volumeDir, tokens.ClaudeFile)
	if exists(keyFile) && !askAgain {
		return nil
	}
	t, err := openTTY()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: no Claude API key for this project yet - run `sandbox --claude-api-key` from a terminal")
		return nil
	}
	defer t.Close()
	_, _ = io.WriteString(t, "sandbox: Claude Code here uses an API key that stays outside the sandbox.\n"+
		"Create one for this project at https://platform.claude.com/settings/keys\n"+
		"(a workspace with a spend limit caps what a misbehaving sandbox can spend).\n")
	key := t.readSecret("API key (Enter to skip): ")
	if key != "" && !tokens.Valid(key) {
		_, _ = io.WriteString(t, "sandbox: that doesn't look like an API key, not saved\n")
		key = ""
	}
	if key == "" {
		if !exists(keyFile) {
			_, _ = io.WriteString(t, "sandbox: no key - Claude Code inside can't reach the API until `sandbox --claude-api-key` sets one\n")
		}
		return nil
	}
	return tokens.Write(keyFile, key)
}
