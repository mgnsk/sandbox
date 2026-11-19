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

func TestHostGitFill(t *testing.T) {
	h := hostGit{Name: "Host", Email: "host@example.com", SigningKey: "ssh-ed25519 AAAAhost"}
	env := &localConfig{GitUserName: "Mine", GitSigningKeyCommand: "op read x"}
	h.fill(env)
	if env.GitUserName != "Mine" || env.GitUserEmail != "host@example.com" || env.GitSigningKey != "" {
		t.Errorf("%+v", env)
	}
	on, off := true, false
	for _, tc := range []struct {
		env  *localConfig
		m    *manifest
		want bool
	}{
		{nil, nil, false},
		{nil, &manifest{GitFromHost: true}, true},
		{&localConfig{GitFromHost: &off}, &manifest{GitFromHost: true}, false},
		{&localConfig{GitFromHost: &on}, nil, true},
		{&localConfig{}, &manifest{GitFromHost: true}, true},
	} {
		if got := gitFromHost(tc.env, tc.m); got != tc.want {
			t.Errorf("%+v %+v: %v", tc.env, tc.m, got)
		}
	}
	if env, err := parseLocalConfig([]byte("git:\n  fromHost: false\n")); err != nil || env.GitFromHost == nil || *env.GitFromHost {
		t.Errorf("%+v %v", env, err)
	}
}
