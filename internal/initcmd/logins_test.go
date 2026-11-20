package initcmd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGhLogins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GH_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, hosts := ghLogins(home); hosts != nil {
		t.Errorf("no file: %v", hosts)
	}
	// What gh leaves after logging out of every host.
	write(t, filepath.Join(home, ".config/gh/hosts.yml"), "{}\n")
	if _, hosts := ghLogins(home); len(hosts) != 0 {
		t.Errorf("logged out: %v", hosts)
	}
	// A keyring login: the token isn't in the file, the host is.
	write(t, filepath.Join(home, ".config/gh/hosts.yml"), "github.com:\n    users:\n        me:\n    user: me\nghe.example:\n    oauth_token: x\n")
	if path, hosts := ghLogins(home); !slices.Equal(hosts, []string{"ghe.example", "github.com"}) || path != filepath.Join(home, ".config/gh/hosts.yml") {
		t.Errorf("%s: %v", path, hosts)
	}
	dir := t.TempDir()
	t.Setenv("GH_CONFIG_DIR", dir)
	if _, hosts := ghLogins(home); hosts != nil {
		t.Errorf("GH_CONFIG_DIR: %v", hosts)
	}
}

func TestFjLogins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "")
	path := filepath.Join(home, ".local/share/forgejo-cli/keys.json")
	write(t, path, `{"hosts":{},"aliases":{}}`)
	if _, hosts := fjLogins(home); len(hosts) != 0 {
		t.Errorf("logged out: %v", hosts)
	}
	write(t, path, `{"hosts":{"codeberg.org":{"type":"Application","name":"me","token":"x"}},"default_ssh":[]}`)
	if got, hosts := fjLogins(home); !slices.Equal(hosts, []string{"codeberg.org"}) || got != path {
		t.Errorf("%s: %v", got, hosts)
	}
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	if _, hosts := fjLogins(home); hosts != nil {
		t.Errorf("XDG_DATA_HOME: %v", hosts)
	}
}
