package launcher

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mgnsk/sandbox/internal/hostname"
	"github.com/mgnsk/sandbox/internal/tokens"
)

// tokenCommands are shell commands run on the host at each start, each
// printing a token for an API guard; a Claude API key command puts Claude
// Code on that key. They come from the user's config (a profile's, or the
// top level's: trusted, run as they are) or from the project - a user's
// .sandbox.yml over its sandbox.nix - and those run only once approved on
// the terminal (see approve). The user's config's win.
type tokenCommands struct {
	GitHubTokenCommand string `json:"githubTokenCommand,omitempty"`
	// By host[:port].
	ForgejoTokenCommands map[string]string `json:"forgejoTokenCommands,omitempty"`
	ClaudeAPIKeyCommand  string            `json:"claudeApiKeyCommand,omitempty"`
}

// over is t with base's command wherever t has none: per guard, and per
// Forgejo host.
func (t tokenCommands) over(base tokenCommands) tokenCommands {
	if t.GitHubTokenCommand == "" {
		t.GitHubTokenCommand = base.GitHubTokenCommand
	}
	if t.ClaudeAPIKeyCommand == "" {
		t.ClaudeAPIKeyCommand = base.ClaudeAPIKeyCommand
	}
	if len(base.ForgejoTokenCommands) > 0 {
		all := maps.Clone(base.ForgejoTokenCommands)
		maps.Copy(all, t.ForgejoTokenCommands)
		t.ForgejoTokenCommands = all
	}
	return t
}

// without is t less the commands that wouldn't run, because over has one
// for that guard or host: they're neither asked about nor run.
func (t tokenCommands) without(over tokenCommands) tokenCommands {
	if over.GitHubTokenCommand != "" {
		t.GitHubTokenCommand = ""
	}
	if over.ClaudeAPIKeyCommand != "" {
		t.ClaudeAPIKeyCommand = ""
	}
	t.ForgejoTokenCommands = maps.Clone(t.ForgejoTokenCommands)
	maps.DeleteFunc(t.ForgejoTokenCommands, func(host, _ string) bool {
		_, ok := over.ForgejoTokenCommands[host]
		return ok
	})
	return t
}

func (t tokenCommands) empty() bool {
	return t.GitHubTokenCommand == "" && len(t.ForgejoTokenCommands) == 0 && t.ClaudeAPIKeyCommand == ""
}

// check tidies t as a project's file has it - commands trimmed, Forgejo
// hosts as host[:port] - and says what's wrong with it.
func (t *tokenCommands) check() error {
	hosts, err := forgejoHosts("guards.forgejo.tokenCommands", t.ForgejoTokenCommands)
	if err != nil {
		return err
	}
	t.ForgejoTokenCommands = hosts
	t.GitHubTokenCommand = strings.TrimSpace(t.GitHubTokenCommand)
	t.ClaudeAPIKeyCommand = strings.TrimSpace(t.ClaudeAPIKeyCommand)
	for host, c := range hosts {
		if hosts[host] = strings.TrimSpace(c); hosts[host] == "" {
			return fmt.Errorf("guards.forgejo.tokenCommands.%q is empty", host)
		}
		if err := checkCommand(c); err != nil {
			return err
		}
	}
	return errors.Join(checkCommand(t.GitHubTokenCommand), checkCommand(t.ClaudeAPIKeyCommand))
}

// checkCommand refuses a command that wouldn't show on the terminal as it
// is (see plainText): it's approved there before it runs.
func checkCommand(c string) error {
	if !plainText(c) {
		return fmt.Errorf("a command with control characters: %q", c)
	}
	return nil
}

// forgejoHosts is commands keyed by normalized host[:port]; nil for none.
func forgejoHosts(from string, commands map[string]string) (map[string]string, error) {
	if len(commands) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(commands))
	for name, c := range commands {
		host, ok := hostname.Normalize(name)
		if !ok {
			return nil, fmt.Errorf("%s: not a Forgejo host: %q", from, name)
		}
		out[host] = c
	}
	return out, nil
}

// runTokenCommand runs command with bash on the host, as the user, with the
// launcher's own environment (the host's PATH, so e.g. `op` is the user's)
// and terminal (so it can prompt); the token it prints. Nothing is written
// anywhere: the token goes to its guard over a pipe.
func (l *launcher) runTokenCommand(ctx context.Context, what, command string) (string, error) {
	token, err := l.runHostCommand(ctx, what, command)
	if err != nil {
		return "", err
	}
	if !tokens.Valid(token) {
		return "", fmt.Errorf("%s (%s) didn't print a token", what, command)
	}
	return token, nil
}

// runHostCommand runs command with bash on the host, from /, with the
// user's environment and terminal; its output, trimmed.
func (l *launcher) runHostCommand(ctx context.Context, what, command string) (string, error) {
	cmd := exec.CommandContext(ctx, l.cfg.Tools.Bash, "-c", command)
	// From /, never the project: nothing the sandbox wrote there (a
	// .git/config, an .envrc, a tool's project config) reaches the command.
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", errors.New("interrupted")
		}
		return "", fmt.Errorf("%s (%s): %w", what, command, err)
	}
	return strings.TrimSpace(out.String()), nil
}

// claudeKeySettings binds a copy of claudeDir's managed settings with the
// apiKeyHelper placeholder over the original, when they lack it: a key
// command from .sandbox.yml comes with no managed config of its own (one
// from the user's config or sandbox.nix already has it). Without it Claude
// Code would ask to log in.
func claudeKeySettings(g *guards, a *bwrapArgs, claudeDir string) error {
	path := filepath.Join(claudeDir, "managed-settings.json")
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	settings := map[string]any{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	if _, ok := settings["apiKeyHelper"]; ok {
		return nil
	}
	settings["apiKeyHelper"] = "echo sandbox-placeholder"
	dir, err := g.tempdir()
	if err != nil {
		return err
	}
	out := filepath.Join(dir, "managed-settings.json")
	if data, err = json.Marshal(settings, json.Deterministic(true)); err != nil {
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	a.roBind(out, "/etc/claude-code/managed-settings.json")
	return nil
}
