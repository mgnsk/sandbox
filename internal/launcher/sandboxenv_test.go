package launcher

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const signingKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk me@example.com"

func TestParseSandboxEnv(t *testing.T) {
	env, err := parseSandboxEnv([]byte(`# Mine, not committed.
GH_TOKEN_COMMAND=op read "op://Employee/GitHub/token"
export CLAUDE_API_KEY_COMMAND='op read op://Employee/Claude/key'
FORGEJO_TOKEN_COMMAND_Codeberg.org = op read op://Employee/Codeberg/token

GIT_USER_NAME="Some One"
GIT_USER_EMAIL=some.one@example.com
GIT_SIGNING_KEY=` + signingKey + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := sandboxEnv{
		GitHubTokenCommand:   `op read "op://Employee/GitHub/token"`,
		ClaudeAPIKeyCommand:  "op read op://Employee/Claude/key",
		ForgejoTokenCommands: map[string]string{"codeberg.org": "op read op://Employee/Codeberg/token"},
		GitUserName:          "Some One",
		GitUserEmail:         "some.one@example.com",
		GitSigningKey:        signingKey,
	}
	if env.GitHubTokenCommand != want.GitHubTokenCommand || env.ClaudeAPIKeyCommand != want.ClaudeAPIKeyCommand ||
		!maps.Equal(env.ForgejoTokenCommands, want.ForgejoTokenCommands) || env.GitUserName != want.GitUserName ||
		env.GitUserEmail != want.GitUserEmail || env.GitSigningKey != want.GitSigningKey {
		t.Errorf("got %+v", env)
	}

	for content, wantErr := range map[string]string{
		"GH_TOKEN=x\n":                         "line 1: unknown key GH_TOKEN",
		"GIT_USER_NAME\n":                      "line 1: want KEY=VALUE",
		"GIT_USER_NAME=a\nGIT_USER_NAME=b\n":   "line 2: GIT_USER_NAME set twice",
		"GH_TOKEN_COMMAND=\n":                  "line 1: GH_TOKEN_COMMAND is empty",
		"GIT_SIGNING_KEY=~/.ssh/id_ed25519\n":  "must be an ssh public key",
		"FORGEJO_TOKEN_COMMAND_not a host=x\n": "not a Forgejo host",
		"GIT_SIGNING_KEY=" + signingKey + "\nGIT_SIGNING_KEY_COMMAND=x\n": "set one",
	} {
		if _, err := parseSandboxEnv([]byte(content)); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%q: %v", content, err)
		}
	}
}

func TestSandboxEnvGit(t *testing.T) {
	env := &sandboxEnv{GitUserName: "Some One", GitUserEmail: "a@example.com", GitSigningKey: signingKey}
	// After the profile's own git config entries.
	inside := map[string]string{"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "pull.rebase", "GIT_CONFIG_VALUE_0": "true"}
	env.setGit(inside)
	want := map[string]string{
		"GIT_AUTHOR_NAME": "Some One", "GIT_COMMITTER_NAME": "Some One",
		"GIT_AUTHOR_EMAIL": "a@example.com", "GIT_COMMITTER_EMAIL": "a@example.com",
		"GIT_CONFIG_COUNT": "5",
		"GIT_CONFIG_KEY_0": "pull.rebase", "GIT_CONFIG_VALUE_0": "true",
		"GIT_CONFIG_KEY_1": "user.signingKey", "GIT_CONFIG_VALUE_1": signingKey,
		"GIT_CONFIG_KEY_2": "gpg.format", "GIT_CONFIG_VALUE_2": "ssh",
		"GIT_CONFIG_KEY_3": "commit.gpgSign", "GIT_CONFIG_VALUE_3": "true",
		"GIT_CONFIG_KEY_4": "tag.gpgSign", "GIT_CONFIG_VALUE_4": "true",
	}
	if !maps.Equal(inside, want) {
		t.Errorf("got %v", inside)
	}
	// Only what's set.
	inside = map[string]string{}
	(&sandboxEnv{GitUserEmail: "a@example.com"}).setGit(inside)
	if !maps.Equal(inside, map[string]string{"GIT_AUTHOR_EMAIL": "a@example.com", "GIT_COMMITTER_EMAIL": "a@example.com"}) {
		t.Errorf("got %v", inside)
	}
}

func TestReadSandboxEnvRefusesALink(t *testing.T) {
	dir := t.TempDir()
	if env, err := readSandboxEnv(dir); env != nil || err != nil {
		t.Errorf("none: %v %v", env, err)
	}
	os.WriteFile(filepath.Join(dir, "elsewhere"), []byte("GIT_USER_NAME=x\n"), 0o644)
	os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, sandboxEnvFileName))
	if _, err := readSandboxEnv(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("link: %v", err)
	}
}

func TestClaudeKeySettings(t *testing.T) {
	g := &guards{}
	defer func() {
		for _, d := range g.dirs {
			os.RemoveAll(d)
		}
	}()
	claudeDir := t.TempDir()
	os.WriteFile(filepath.Join(claudeDir, "managed-settings.json"), []byte(`{"env": {"A": "1"}}`), 0o644)
	var a bwrapArgs
	if err := claudeKeySettings(g, &a, claudeDir); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(a, " ")
	if !strings.Contains(args, "/etc/claude-code/managed-settings.json") || len(g.dirs) != 1 {
		t.Fatalf("%q", args)
	}
	data, _ := os.ReadFile(filepath.Join(g.dirs[0], "managed-settings.json"))
	if got := string(data); got != `{"apiKeyHelper":"echo sandbox-placeholder","env":{"A":"1"}}` {
		t.Errorf("%s", got)
	}
	// Already there (the user's config's key, or sandbox.nix's): left alone.
	os.WriteFile(filepath.Join(claudeDir, "managed-settings.json"), []byte(`{"apiKeyHelper": "x"}`), 0o644)
	a = bwrapArgs{}
	if err := claudeKeySettings(g, &a, claudeDir); err != nil || len(a) != 0 {
		t.Errorf("%v %q", err, a)
	}
}
