package launcher

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const signingKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk me@example.com"

func TestParseLocalConfig(t *testing.T) {
	c, err := parseLocalConfig([]byte(`# Mine, not committed.
guards:
  github:
    tokenCommand: op read "op://Employee/GitHub/token"
  claudeApiKey:
    tokenCommand: 'op read op://Employee/Claude/key'
  forgejo:
    tokenCommands:
      Codeberg.org: op read op://Employee/Codeberg/token
git:
  fromHost: false
  userName: Some One
  userEmail: some.one@example.com
  signingKey: ` + signingKey + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.GitHubTokenCommand != `op read "op://Employee/GitHub/token"` || c.ClaudeAPIKeyCommand != "op read op://Employee/Claude/key" ||
		!maps.Equal(c.ForgejoTokenCommands, map[string]string{"codeberg.org": "op read op://Employee/Codeberg/token"}) ||
		c.Git.UserName != "Some One" || c.Git.UserEmail != "some.one@example.com" || c.Git.SigningKey != signingKey ||
		c.Git.FromHost == nil || *c.Git.FromHost {
		t.Errorf("got %+v", c)
	}
	if c, err := parseLocalConfig(nil); err != nil || c.Git.FromHost != nil || !c.tokenCommands.empty() {
		t.Errorf("empty: %+v %v", c, err)
	}

	for content, wantErr := range map[string]string{
		"guards:\n  gitHub:\n    tokenCommand: x\n":                        "field gitHub not found",
		"git:\n  username: x\n":                                            "field username not found",
		"git:\n  fromHost: maybe\n":                                        "cannot unmarshal",
		"git:\n  signingKey: ~/.ssh/id_ed25519\n":                          "must be an ssh public key",
		"guards:\n  forgejo:\n    tokenCommands:\n      not a host: x\n":   "not a Forgejo host",
		"guards:\n  forgejo:\n    tokenCommands:\n      a.example: ''\n":   "is empty",
		"git:\n  signingKey: " + signingKey + "\n  signingKeyCommand: x\n": "set one",
		"git: [\n": "yaml",
	} {
		if _, err := parseLocalConfig([]byte(content)); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%q: %v", content, err)
		}
	}
}

func TestGitEnv(t *testing.T) {
	git := gitSettings{UserName: "Some One", UserEmail: "a@example.com", SigningKey: signingKey}
	// After the profile's own git config entries.
	inside := map[string]string{"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "pull.rebase", "GIT_CONFIG_VALUE_0": "true"}
	git.setEnv(inside)
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
	gitSettings{UserEmail: "a@example.com"}.setEnv(inside)
	if !maps.Equal(inside, map[string]string{"GIT_AUTHOR_EMAIL": "a@example.com", "GIT_COMMITTER_EMAIL": "a@example.com"}) {
		t.Errorf("got %v", inside)
	}
}

func TestReadLocalConfigRefusesALink(t *testing.T) {
	dir := t.TempDir()
	if c, err := readLocalConfig(dir); err != nil || !c.tokenCommands.empty() || c.Git != (gitSettings{}) {
		t.Errorf("none: %+v %v", c, err)
	}
	os.WriteFile(filepath.Join(dir, "elsewhere"), []byte("git:\n  userName: x\n"), 0o644)
	os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, localConfigFileName))
	if _, err := readLocalConfig(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
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
