package launcher

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"
)

// sandboxEnvFileName is a project's per-user settings: next to sandbox.nix,
// meant to be gitignored, so each user of a project sets their own token
// commands (their secret manager's item paths) and git identity.
const sandboxEnvFileName = ".sandbox.env"

// sandboxEnv is what .sandbox.env sets. It's in the project, which the
// sandbox can write, so it's read like sandbox.nix: never through a
// symlink, never run by a shell, every key known; its token commands run
// on the host only once approved, like sandbox.nix's. The git settings only
// affect the inside.
type sandboxEnv struct {
	GitHubTokenCommand   string
	ForgejoTokenCommands map[string]string
	ClaudeAPIKeyCommand  string
	GitUserName          string
	GitUserEmail         string
	GitSigningKey        string // An ssh public key, signing through the agent.
	// Prints GitSigningKey on the host at start; approved like the token
	// commands.
	GitSigningKeyCommand string
}

const forgejoTokenCommandPrefix = "FORGEJO_TOKEN_COMMAND_"

// readSandboxEnv reads the project's .sandbox.env; nil without one.
func readSandboxEnv(project string) (*sandboxEnv, error) {
	path := filepath.Join(project, sandboxEnvFileName)
	if !lexists(path) {
		return nil, nil
	}
	data, err := readProjectFile(path)
	if err != nil {
		return nil, err
	}
	env, err := parseSandboxEnv(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return env, nil
}

// parseSandboxEnv parses KEY=VALUE lines: blank lines and # comments
// skipped, an optional `export `, the value taken literally - optionally
// in matching single or double quotes, which are stripped, nothing else
// interpreted.
func parseSandboxEnv(data []byte) (*sandboxEnv, error) {
	env := &sandboxEnv{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("line %d: want KEY=VALUE", n)
		}
		if seen[key] {
			return nil, fmt.Errorf("line %d: %s set twice", n, key)
		}
		seen[key] = true
		value = unquote(strings.TrimSpace(value))
		if value == "" {
			return nil, fmt.Errorf("line %d: %s is empty", n, key)
		}
		switch {
		case key == "GH_TOKEN_COMMAND":
			env.GitHubTokenCommand = value
		case key == "CLAUDE_API_KEY_COMMAND":
			env.ClaudeAPIKeyCommand = value
		case strings.HasPrefix(key, forgejoTokenCommandPrefix):
			if env.ForgejoTokenCommands == nil {
				env.ForgejoTokenCommands = map[string]string{}
			}
			env.ForgejoTokenCommands[strings.TrimPrefix(key, forgejoTokenCommandPrefix)] = value
		case key == "GIT_USER_NAME":
			env.GitUserName = value
		case key == "GIT_USER_EMAIL":
			env.GitUserEmail = value
		case key == "GIT_SIGNING_KEY":
			if !isSSHPublicKey(value) {
				return nil, fmt.Errorf("line %d: GIT_SIGNING_KEY must be an ssh public key (ssh-ed25519 AAAA...)", n)
			}
			env.GitSigningKey = value
		case key == "GIT_SIGNING_KEY_COMMAND":
			env.GitSigningKeyCommand = value
		default:
			return nil, fmt.Errorf("line %d: unknown key %s", n, key)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if env.GitSigningKey != "" && env.GitSigningKeyCommand != "" {
		return nil, errors.New("GIT_SIGNING_KEY and GIT_SIGNING_KEY_COMMAND: set one")
	}
	hosts, err := forgejoHosts(forgejoTokenCommandPrefix+"<host>", env.ForgejoTokenCommands)
	if err != nil {
		return nil, err
	}
	if len(hosts) > 0 {
		env.ForgejoTokenCommands = hosts
	}
	return env, nil
}

func unquote(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}

func isSSHPublicKey(key string) bool {
	kind, data, ok := strings.Cut(key, " ")
	return ok && data != "" && (strings.HasPrefix(kind, "ssh-") || strings.HasPrefix(kind, "ecdsa-") ||
		strings.HasPrefix(kind, "sk-"))
}

// overlay puts env's token commands over sandbox.nix's in m: they're the
// user's, for this project. They're still the project's to the launcher,
// approved before they run.
func (env *sandboxEnv) overlay(m *manifest) {
	if env.GitHubTokenCommand != "" {
		m.GitHubTokenCommand = env.GitHubTokenCommand
	}
	if env.ClaudeAPIKeyCommand != "" {
		m.ClaudeAPIKeyCommand = env.ClaudeAPIKeyCommand
	}
	m.GitSigningKeyCommand = env.GitSigningKeyCommand
	if len(env.ForgejoTokenCommands) > 0 {
		all := maps.Clone(m.ForgejoTokenCommands)
		if all == nil {
			all = map[string]string{}
		}
		maps.Copy(all, env.ForgejoTokenCommands)
		m.ForgejoTokenCommands = all
	}
}

// setGit sets env's git identity and signing in the inside environment:
// author and committer, and ssh signing of commits and tags with the
// agent's key, as git config entries after any the profile's env has.
func (env *sandboxEnv) setGit(inside map[string]string) {
	if env.GitUserName != "" {
		inside["GIT_AUTHOR_NAME"] = env.GitUserName
		inside["GIT_COMMITTER_NAME"] = env.GitUserName
	}
	if env.GitUserEmail != "" {
		inside["GIT_AUTHOR_EMAIL"] = env.GitUserEmail
		inside["GIT_COMMITTER_EMAIL"] = env.GitUserEmail
	}
	if env.GitSigningKey == "" {
		return
	}
	count, _ := strconv.Atoi(inside["GIT_CONFIG_COUNT"])
	for _, kv := range [][2]string{
		{"user.signingKey", env.GitSigningKey},
		{"gpg.format", "ssh"},
		{"commit.gpgSign", "true"},
		{"tag.gpgSign", "true"},
	} {
		inside[fmt.Sprintf("GIT_CONFIG_KEY_%d", count)] = kv[0]
		inside[fmt.Sprintf("GIT_CONFIG_VALUE_%d", count)] = kv[1]
		count++
	}
	inside["GIT_CONFIG_COUNT"] = strconv.Itoa(count)
}

// resolveSigningKey runs the (approved) signing key command, if any, for
// GitSigningKey: its output must be an ssh public key.
func (env *sandboxEnv) resolveSigningKey(ctx context.Context, l *launcher) error {
	if env.GitSigningKeyCommand == "" {
		return nil
	}
	key, err := l.runHostCommand(ctx, "GIT_SIGNING_KEY_COMMAND", env.GitSigningKeyCommand)
	if err != nil {
		return err
	}
	if !isSSHPublicKey(key) || strings.Contains(key, "\n") {
		return fmt.Errorf("GIT_SIGNING_KEY_COMMAND (%s) didn't print an ssh public key", env.GitSigningKeyCommand)
	}
	env.GitSigningKey = key
	return nil
}
