package launcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeGit puts a git on PATH answering `config --global --get KEY` from
// values (exit 1 for a missing one) and noting the directory it ran in.
func fakeGit(t *testing.T, values map[string]string) (cwdLog string) {
	t.Helper()
	bin := t.TempDir()
	cwdLog = filepath.Join(bin, "cwd")
	script := "#!/bin/sh\npwd >> " + cwdLog + "\n[ \"$1 $2 $3\" = \"config --global --get\" ] || exit 2\ncase \"$4\" in\n"
	for k, v := range values {
		script += "  " + k + ") echo '" + v + "' ;;\n"
	}
	script += "  *) exit 1 ;;\nesac\n"
	os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return cwdLog
}

func TestReadHostGit(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh/id_ed25519.pub"), []byte(signingKey+"\n"), 0o644)
	cwdLog := fakeGit(t, map[string]string{
		"user.name": "Some One", "user.email": "a@example.com",
		"gpg.format": "ssh", "user.signingKey": "~/.ssh/id_ed25519",
	})
	t.Chdir(home)
	got := readHostGit(context.Background(), home)
	if got != (hostGit{Name: "Some One", Email: "a@example.com", SigningKey: signingKey}) {
		t.Errorf("got %+v", got)
	}
	if log, _ := os.ReadFile(cwdLog); string(log) != "/\n/\n/\n/\n" {
		t.Errorf("ran in %q", log)
	}

	// Not ssh signing: no key. Nothing set: nothing.
	fakeGit(t, map[string]string{"user.name": "N", "user.signingKey": "ABCDEF12"})
	if got := readHostGit(context.Background(), home); got != (hostGit{Name: "N"}) {
		t.Errorf("gpg: %+v", got)
	}
	t.Setenv("PATH", t.TempDir())
	if got := readHostGit(context.Background(), home); got != (hostGit{}) {
		t.Errorf("no git: %+v", got)
	}
}

func TestSSHSigningKey(t *testing.T) {
	home := t.TempDir()
	pub := filepath.Join(home, "k.pub")
	os.WriteFile(pub, []byte(signingKey+"\n"), 0o644)
	os.Symlink(pub, filepath.Join(home, "link.pub"))
	os.WriteFile(filepath.Join(home, "bad.pub"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600)
	for value, want := range map[string]string{
		signingKey:                      signingKey,
		"key::" + signingKey:            signingKey,
		pub:                             signingKey,
		filepath.Join(home, "k"):        signingKey, // The private key's path: its .pub.
		"~/k.pub":                       signingKey,
		filepath.Join(home, "link.pub"): "", // Not through a link.
		filepath.Join(home, "bad"):      "",
		"relative/k.pub":                "",
		"":                              "",
	} {
		if got := sshSigningKey(value, home); got != want {
			t.Errorf("%q: %q", value, got)
		}
	}
}

// Git's settings: a user's .sandbox.yml over sandbox.nix's, and the host's
// identity under both, where they ask for it.
func TestGitSettings(t *testing.T) {
	h := hostGit{Name: "Host", Email: "host@example.com", SigningKey: "ssh-ed25519 AAAAhost"}
	// Explicit settings win, and a signing key or command of one's own
	// keeps the host's key out.
	got := gitSettings{UserName: "Mine", SigningKeyCommand: "op read x"}.withHost(h)
	if got.UserName != "Mine" || got.UserEmail != "host@example.com" || got.SigningKey != "" {
		t.Errorf("%+v", got)
	}
	if got := (gitSettings{}).withHost(h); got.SigningKey != h.SigningKey {
		t.Errorf("%+v", got)
	}

	on, off := true, false
	for _, tc := range []struct {
		local gitSettings
		m     manifest
		want  bool
	}{
		{gitSettings{}, manifest{}, false},
		{gitSettings{}, manifest{GitFromHost: true}, true},
		{gitSettings{FromHost: &off}, manifest{GitFromHost: true}, false},
		{gitSettings{FromHost: &on}, manifest{}, true},
	} {
		if got := tc.local.over(tc.m.git()).fromHost(); got != tc.want {
			t.Errorf("%+v %+v: %v", tc.local, tc.m, got)
		}
	}
	if c, err := parseLocalConfig([]byte("git:\n  fromHost: false\n")); err != nil || c.Git.FromHost == nil || *c.Git.FromHost {
		t.Errorf("%+v %v", c, err)
	}

	// Either a key or a command of one's own replaces both of
	// sandbox.nix's.
	theirs := (&manifest{GitSigningKey: "ssh-ed25519 AAAAteam"}).git()
	theirCommand := (&manifest{GitSigningKeyCommand: "team"}).git()
	for _, tc := range []struct {
		local, base gitSettings
		key, cmd    string
	}{
		{gitSettings{}, theirs, "ssh-ed25519 AAAAteam", ""},
		{gitSettings{}, theirCommand, "", "team"},
		{gitSettings{SigningKey: "ssh-ed25519 AAAAmine"}, theirCommand, "ssh-ed25519 AAAAmine", ""},
		{gitSettings{SigningKeyCommand: "mine"}, theirs, "", "mine"},
	} {
		if got := tc.local.over(tc.base); got.SigningKey != tc.key || got.SigningKeyCommand != tc.cmd {
			t.Errorf("%+v over %+v: %+v", tc.local, tc.base, got)
		}
	}
}
