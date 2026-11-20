package launcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// localConfigFileName is a project's per-user settings: next to
// sandbox.nix, meant to be gitignored, so each user of a project sets their
// own token commands (their secret manager's item paths) and git identity.
const localConfigFileName = ".sandbox.yml"

// localConfig is what .sandbox.yml sets, in sandbox.nix's option names.
// It's in the project, which the sandbox can write, so it's read like
// sandbox.nix: never through a symlink, every field known; its commands run
// on the host only once approved, like sandbox.nix's. The git settings only
// affect the inside.
type localConfig struct {
	GitHubTokenCommand   string
	ForgejoTokenCommands map[string]string
	ClaudeAPIKeyCommand  string
	GitUserName          string
	GitUserEmail         string
	GitSigningKey        string // An ssh public key, signing through the agent.
	// Prints GitSigningKey on the host at start; approved like the token
	// commands.
	GitSigningKeyCommand string
	// Fill the git settings it doesn't have from the host's global git
	// config (see hostGit); nil leaves it to sandbox.nix.
	GitFromHost *bool
}

// localConfigFile is .sandbox.yml's layout.
type localConfigFile struct {
	Guards struct {
		GitHub struct {
			TokenCommand string `yaml:"tokenCommand"`
		} `yaml:"github"`
		Forgejo struct {
			TokenCommands map[string]string `yaml:"tokenCommands"`
		} `yaml:"forgejo"`
		ClaudeAPIKey struct {
			TokenCommand string `yaml:"tokenCommand"`
		} `yaml:"claudeApiKey"`
	} `yaml:"guards"`
	Git struct {
		FromHost          *bool  `yaml:"fromHost"`
		UserName          string `yaml:"userName"`
		UserEmail         string `yaml:"userEmail"`
		SigningKey        string `yaml:"signingKey"`
		SigningKeyCommand string `yaml:"signingKeyCommand"`
	} `yaml:"git"`
}

// readLocalConfig reads the project's .sandbox.yml; nil without one.
func readLocalConfig(project string) (*localConfig, error) {
	path := filepath.Join(project, localConfigFileName)
	if !lexists(path) {
		return nil, nil
	}
	data, err := readProjectFile(path)
	if err != nil {
		return nil, err
	}
	env, err := parseLocalConfig(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return env, nil
}

// parseLocalConfig parses .sandbox.yml strictly: an unknown field (a typo)
// is an error, not a setting quietly ignored.
func parseLocalConfig(data []byte) (*localConfig, error) {
	var f localConfigFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	c := &localConfig{
		GitHubTokenCommand:   strings.TrimSpace(f.Guards.GitHub.TokenCommand),
		ClaudeAPIKeyCommand:  strings.TrimSpace(f.Guards.ClaudeAPIKey.TokenCommand),
		GitUserName:          strings.TrimSpace(f.Git.UserName),
		GitUserEmail:         strings.TrimSpace(f.Git.UserEmail),
		GitSigningKey:        strings.TrimSpace(f.Git.SigningKey),
		GitSigningKeyCommand: strings.TrimSpace(f.Git.SigningKeyCommand),
		GitFromHost:          f.Git.FromHost,
	}
	if c.GitSigningKey != "" && !isSSHPublicKey(c.GitSigningKey) {
		return nil, errors.New("git.signingKey must be an ssh public key (ssh-ed25519 AAAA...)")
	}
	if c.GitSigningKey != "" && c.GitSigningKeyCommand != "" {
		return nil, errors.New("git.signingKey and git.signingKeyCommand: set one")
	}
	for host, command := range f.Guards.Forgejo.TokenCommands {
		if strings.TrimSpace(command) == "" {
			return nil, fmt.Errorf("guards.forgejo.tokenCommands.%q is empty", host)
		}
	}
	// Shown on the terminal for approval, like sandbox.nix's (see
	// plainText).
	commands := slices.Collect(maps.Values(f.Guards.Forgejo.TokenCommands))
	for _, command := range append(commands, c.GitHubTokenCommand, c.ClaudeAPIKeyCommand, c.GitSigningKeyCommand) {
		if !plainText(command) {
			return nil, fmt.Errorf("a command with control characters: %q", command)
		}
	}
	hosts, err := forgejoHosts("guards.forgejo.tokenCommands", f.Guards.Forgejo.TokenCommands)
	if err != nil {
		return nil, err
	}
	if len(hosts) > 0 {
		c.ForgejoTokenCommands = hosts
	}
	return c, nil
}

func isSSHPublicKey(key string) bool {
	kind, data, ok := strings.Cut(key, " ")
	return ok && data != "" && (strings.HasPrefix(kind, "ssh-") || strings.HasPrefix(kind, "ecdsa-") ||
		strings.HasPrefix(kind, "sk-"))
}

// overlay puts env's token commands over sandbox.nix's in m: they're the
// user's, for this project. They're still the project's to the launcher,
// approved before they run.
func (env *localConfig) overlay(m *manifest) {
	if env.GitHubTokenCommand != "" {
		m.GitHubTokenCommand = env.GitHubTokenCommand
	}
	if env.ClaudeAPIKeyCommand != "" {
		m.ClaudeAPIKeyCommand = env.ClaudeAPIKeyCommand
	}
	// Either of its own replaces sandbox.nix's key and command both.
	if env.GitSigningKey != "" || env.GitSigningKeyCommand != "" {
		m.GitSigningKey, m.GitSigningKeyCommand = "", env.GitSigningKeyCommand
	}
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
func (env *localConfig) setGit(inside map[string]string) {
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
func (env *localConfig) resolveSigningKey(ctx context.Context, l *launcher) error {
	if env.GitSigningKeyCommand == "" {
		return nil
	}
	key, err := l.runHostCommand(ctx, "git.signingKeyCommand", env.GitSigningKeyCommand)
	if err != nil {
		return err
	}
	if !isSSHPublicKey(key) || strings.Contains(key, "\n") {
		return fmt.Errorf("git.signingKeyCommand (%s) didn't print an ssh public key", env.GitSigningKeyCommand)
	}
	env.GitSigningKey = key
	return nil
}

// withProjectSigning is env (nil for none) with sandbox.nix's approved
// signing key or command when it has neither of its own; nil if neither
// sets anything.
func withProjectSigning(env *localConfig, m *manifest) *localConfig {
	if m == nil || m.GitSigningKey == "" && m.GitSigningKeyCommand == "" {
		return env
	}
	if env == nil {
		env = &localConfig{}
	}
	if env.GitSigningKey == "" && env.GitSigningKeyCommand == "" {
		env.GitSigningKey, env.GitSigningKeyCommand = m.GitSigningKey, m.GitSigningKeyCommand
	}
	return env
}
