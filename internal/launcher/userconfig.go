package launcher

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

const userConfigFile = "config.nix"

// userConfigFiles lists every file under dir (through symlinks to files,
// which dotfiles managers make), in order: what the cache key covers.
func userConfigFiles(dir string) []string {
	var files []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && isFile(path) {
			files = append(files, path)
		}
		return nil
	})
	return files
}

func xdgDir(env, home, fallback string) string {
	if dir := os.Getenv(env); dir != "" {
		return dir
	}
	return filepath.Join(home, fallback)
}

// userConfig switches to the config built from ~/.config/sandbox/config.nix
// when this sandbox takes one and it exists. Cached until a file in
// ~/.config/sandbox or this sandbox changes; imports from outside that dir
// aren't tracked, --reload picks them up.
func (l *launcher) userConfig(ctx context.Context) error {
	if l.cfg.UserConfig == nil {
		return nil
	}
	configDir := filepath.Join(xdgDir("XDG_CONFIG_HOME", l.home, ".config"), "sandbox")
	file := filepath.Join(configDir, userConfigFile)
	if !isFile(file) {
		return nil
	}
	// Through a link to the dir, which dotfiles managers make too.
	files := userConfigFiles(realpath(configDir))
	// It's built and run on the host: not from anywhere a sandbox can write.
	for _, path := range append([]string{configDir}, files...) {
		if real := realpath(path); within(real, l.project) {
			return fmt.Errorf("refusing to use %s: %s is in this project, which the sandbox can write", file, real)
		}
	}
	type entry struct {
		Path string
		Hash [sha256.Size]byte
	}
	entries := make([]entry, len(files))
	for i, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(realpath(configDir), path)
		entries[i] = entry{rel, sha256.Sum256(data)}
	}
	key := cacheKey(realpath(l.configPath), entries)

	state := filepath.Join(xdgDir("XDG_STATE_HOME", l.home, ".local/state"), "sandbox")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	cache := filepath.Join(state, "config.json")
	out := ""
	if !l.opts.reload {
		out = readCache(cache, key)
	}
	fresh := out == ""
	if fresh {
		var err error
		if out, err = l.buildUserConfig(ctx, file, filepath.Join(state, "config")); err != nil {
			return err
		}
	}
	built, err := readConfig(out)
	if err != nil {
		return fmt.Errorf("bad %s result: %w", file, err)
	}
	if built.UserConfig != nil {
		return fmt.Errorf("bad %s result %s: it takes a config.nix itself", file, out)
	}
	if fresh {
		if err := writeJSON(cache, cached{Key: key, Result: out}); err != nil {
			return err
		}
	}
	l.configPath, l.cfg = out, built
	return nil
}

func (l *launcher) buildUserConfig(ctx context.Context, file, link string) (string, error) {
	nixBuild, err := exec.LookPath("nix-build")
	if err != nil {
		return "", fmt.Errorf("building %s needs nix-build on PATH", file)
	}
	fmt.Fprintf(os.Stderr, "sandbox: building %s\n", file)
	u := l.cfg.UserConfig
	out, err := l.runCapturing(ctx, os.Environ(), nixBuild, u.Eval,
		"--argstr", "nixpkgs", u.Nixpkgs,
		"--argstr", "system", u.System,
		"--argstr", "file", file,
		"--out-link", link,
	)
	if err == nil {
		if out = lastStorePath(out); out == "" {
			err = errors.New("no result")
		}
	}
	if err != nil {
		return "", fmt.Errorf("building %s: %w", file, err)
	}
	return out, nil
}

// runCapturing runs argv with no stdin, its stdout captured and its stderr
// the launcher's. A signal to the launcher interrupts it.
func (l *launcher) runCapturing(ctx context.Context, env []string, argv ...string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stderr = os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", errors.New("interrupted")
	}
	return string(out), err
}
