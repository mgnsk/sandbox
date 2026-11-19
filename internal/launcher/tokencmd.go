package launcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
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
// for a guard that's off, or one the user's config already sets - so
// they're neither asked about nor run.
func projectTokenCommands(cfg *config, prof profile, m *manifest) {
	if !cfg.Guards.GitHub || prof.GitHubTokenCommand != "" {
		m.GitHubTokenCommand = ""
	}
	if !cfg.Guards.Forgejo {
		m.ForgejoTokenCommands = nil
		return
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
	cmd := exec.CommandContext(ctx, l.cfg.Tools.Bash, "-c", command)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", errors.New("interrupted")
		}
		return "", fmt.Errorf("%s (%s): %w", what, command, err)
	}
	token := strings.TrimSpace(out.String())
	if !tokens.Valid(token) {
		return "", fmt.Errorf("%s (%s) didn't print a token", what, command)
	}
	return token, nil
}
