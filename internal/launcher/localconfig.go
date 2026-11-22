package launcher

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// localConfigFileName is a project's per-user settings, in its root and
// meant to be gitignored, so each user of a project sets their own token
// commands (their secret manager's item paths) and git identity.
const localConfigFileName = ".sandbox.yml"

// localConfig is what .sandbox.yml sets, in the configuration's option
// names. It's in the project, which the sandbox can write: it's never read
// through a symlink, every field must be known, and its commands run on the
// host only once approved. The git settings only affect the inside.
type localConfig struct {
	tokenCommands
	Git gitSettings
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

// readLocalConfig reads the project's .sandbox.yml; the zero value without
// one.
func readLocalConfig(project string) (localConfig, error) {
	path := filepath.Join(project, localConfigFileName)
	if !lexists(path) {
		return localConfig{}, nil
	}
	data, err := readProjectFile(path)
	if err != nil {
		return localConfig{}, err
	}
	c, err := parseLocalConfig(data)
	if err != nil {
		return localConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// parseLocalConfig parses .sandbox.yml strictly: an unknown field (a typo)
// is an error, not a setting quietly ignored.
func parseLocalConfig(data []byte) (localConfig, error) {
	var f localConfigFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return localConfig{}, err
	}
	c := localConfig{
		tokenCommands: tokenCommands{
			GitHubTokenCommand:   f.Guards.GitHub.TokenCommand,
			ForgejoTokenCommands: f.Guards.Forgejo.TokenCommands,
			ClaudeAPIKeyCommand:  f.Guards.ClaudeAPIKey.TokenCommand,
		},
		Git: gitSettings{
			UserName:          strings.TrimSpace(f.Git.UserName),
			UserEmail:         strings.TrimSpace(f.Git.UserEmail),
			SigningKey:        strings.TrimSpace(f.Git.SigningKey),
			SigningKeyCommand: strings.TrimSpace(f.Git.SigningKeyCommand),
			FromHost:          f.Git.FromHost,
		},
	}
	if err := errors.Join(c.tokenCommands.check(), c.Git.check()); err != nil {
		return localConfig{}, err
	}
	return c, nil
}
