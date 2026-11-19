package launcher

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// hostGit is the git identity from the user's global git config on the
// host (git.fromHost, in sandbox.nix or .sandbox.yml): name, email, and the ssh public key
// it signs with. Only `git config --global --get` runs, from /, never in
// the project, whose .git the sandbox can write; a value that isn't set,
// or no git on the host, leaves it empty.
type hostGit struct {
	Name, Email, SigningKey string
}

func readHostGit(ctx context.Context, home string) hostGit {
	git, err := exec.LookPath("git")
	if err != nil {
		return hostGit{}
	}
	get := func(key string) string {
		cmd := exec.CommandContext(ctx, git, "config", "--global", "--get", key)
		cmd.Dir = "/"
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	h := hostGit{Name: get("user.name"), Email: get("user.email")}
	if get("gpg.format") == "ssh" {
		h.SigningKey = sshSigningKey(get("user.signingKey"), home)
	}
	return h
}

// sshSigningKey is the public key git's user.signingKey names with
// gpg.format = ssh: the key itself (optionally key::-prefixed), or a key
// file's path, whose .pub is read; "" for anything else.
func sshSigningKey(value, home string) string {
	value = strings.TrimPrefix(value, "key::")
	if isSSHPublicKey(value) {
		return value
	}
	if value == "" {
		return ""
	}
	path := value
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		path = filepath.Join(home, rest)
	}
	if !filepath.IsAbs(path) {
		return ""
	}
	if !strings.HasSuffix(path, ".pub") {
		path += ".pub"
	}
	key := readPublicKey(path)
	if !isSSHPublicKey(key) || strings.Contains(key, "\n") {
		return ""
	}
	return key
}

// readPublicKey reads a small regular file, not through a symlink at its
// last component; "" if it isn't one.
func readPublicKey(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(f, 16<<10))
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}

// fill sets what env doesn't have yet from h: explicit settings win, and a
// signing key or command from .sandbox.yml or sandbox.nix keeps the host's
// key out.
func (h hostGit) fill(env *localConfig) {
	if env.GitUserName == "" {
		env.GitUserName = h.Name
	}
	if env.GitUserEmail == "" {
		env.GitUserEmail = h.Email
	}
	if env.GitSigningKey == "" && env.GitSigningKeyCommand == "" {
		env.GitSigningKey = h.SigningKey
	}
}

// gitFromHost says whether to fill the git settings from the host:
// .sandbox.yml's git.fromHost, else sandbox.nix's.
func gitFromHost(env *localConfig, m *manifest) bool {
	if env != nil && env.GitFromHost != nil {
		return *env.GitFromHost
	}
	return m != nil && m.GitFromHost
}
