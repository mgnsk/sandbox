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

// Token commands are shell commands run on the host at each start, each
// printing a token for an API guard. They come from the user's config
// (home-manager, a flake with mkSandbox: trusted, run as they are) or from
// the project's sandbox.nix (run only once approved on the terminal, see
// approveProject); the user's win.

// forgejoHosts is commands keyed by normalized host[:port].
func forgejoHosts(from string, commands map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(commands))
	for name, c := range commands {
		host, ok := hostname.Normalize(name)
		if !ok {
			return nil, fmt.Errorf("%s: not a Forgejo host: %s", from, name)
		}
		out[host] = c
	}
	return out, nil
}

// projectTokenCommands drops from m the token commands that wouldn't run -
// those the user's config already sets - so they're neither asked about
// nor run.
func projectTokenCommands(prof profile, m *manifest) {
	if prof.GitHubTokenCommand != "" {
		m.GitHubTokenCommand = ""
	}
	// Without Claude Code in the sandbox (no managed config), no key.
	if prof.ClaudeDir == "" || prof.ClaudeAPIKeyCommand != "" {
		m.ClaudeAPIKeyCommand = ""
	}
	for host := range m.ForgejoTokenCommands {
		if _, ok := prof.ForgejoTokenCommands[host]; ok {
			delete(m.ForgejoTokenCommands, host)
		}
	}
}

// withProjectTokenCommands is prof with the approved commands from
// sandbox.nix where the user's config has none.
func withProjectTokenCommands(prof profile, m *manifest) profile {
	if prof.GitHubTokenCommand == "" {
		prof.GitHubTokenCommand = m.GitHubTokenCommand
	}
	if prof.ClaudeAPIKeyCommand == "" {
		prof.ClaudeAPIKeyCommand = m.ClaudeAPIKeyCommand
	}
	if len(m.ForgejoTokenCommands) > 0 {
		all := maps.Clone(m.ForgejoTokenCommands)
		maps.Copy(all, prof.ForgejoTokenCommands)
		prof.ForgejoTokenCommands = all
	}
	return prof
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
