package launcher

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

const projectFileName = "sandbox.nix"

// manifest is what project.nix makes of sandbox.nix.
type manifest struct {
	ClaudeDir string   `json:"claudeDir"`
	Binds     []bind   `json:"binds"`
	HostPorts []string `json:"hostPorts"`
	Command   []string `json:"command"`
}

// readManifest reads a manifest. It comes out of a sandbox, so it's read
// strictly and every field is checked before the launcher uses it.
func readManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("can't read the %s result: %w", projectFileName, err)
	}
	m := &manifest{}
	if err := json.Unmarshal(data, m, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("bad %s result %s: %w", projectFileName, path, err)
	}
	if err := m.check(); err != nil {
		return nil, fmt.Errorf("bad %s result %s: %w", projectFileName, path, err)
	}
	return m, nil
}

func (m *manifest) check() error {
	if m.ClaudeDir != "" && !isStorePath(m.ClaudeDir) {
		return errors.New("claudeDir is not a store path")
	}
	for _, b := range m.Binds {
		if b.Src == "" || b.Mode != "ro" && b.Mode != "rw" {
			return fmt.Errorf("bad bind %+v", b)
		}
	}
	if m.Command != nil && len(m.Command) == 0 {
		return errors.New("empty command")
	}
	return nil
}

// readProjectFile reads sandbox.nix's bytes, for the cache key. Not through
// a symlink, which would have the launcher read a host file of the
// sandbox's choosing.
func readProjectFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("can't read %s (it must be a regular file): %w", path, err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	return io.ReadAll(f)
}

// cached is a cache file's content: the key of what a result was made from.
type cached struct {
	Key    string `json:"key"`
	Result string `json:"result"`
}

// readCache is the store path cached under key in the file at path, or "".
func readCache(path, key string) string {
	data, err := os.ReadFile(path)
	var c cached
	if err != nil || json.Unmarshal(data, &c) != nil || c.Key != key || !isStorePath(c.Result) || !isFile(c.Result) {
		return ""
	}
	return c.Result
}

// projectManifest is sandbox.nix's manifest, from the cache while
// sandbox.nix, the sandbox's own config and the profile's Claude config are
// unchanged. Files sandbox.nix imports aren't tracked; --reload picks them
// up.
func (l *launcher) projectManifest(ctx context.Context, base string) (*manifest, error) {
	projectFile := filepath.Join(l.project, projectFileName)
	content, err := readProjectFile(projectFile)
	if err != nil {
		return nil, err
	}
	key := cacheKey(realpath(l.configPath), base, content)
	cache := filepath.Join(l.volumeDir, "project.json")
	if !l.opts.Reload {
		if out := readCache(cache, key); out != "" {
			return readManifest(out)
		}
	}
	// Evaluated with nix inside a sandbox of the project, without its
	// sandbox.nix.
	fmt.Fprintf(os.Stderr, "sandbox: evaluating %s\n", projectFile)
	out, err := l.runCapturing(ctx,
		l.self, "launch", "--config", l.configPath, "--no-project-config", "--",
		"nix", "build", "--no-link", "--print-out-paths", "--file", l.cfg.Project.Eval,
		"--argstr", "nixpkgs", l.cfg.Project.Nixpkgs,
		"--argstr", "system", l.cfg.Project.System,
		"--argstr", "file", projectFile,
		"--argstr", "base", base,
	)
	if err != nil {
		return nil, fmt.Errorf("evaluating %s: %w", projectFile, err)
	}
	// The login shell's startup files may print too; the build's output is
	// the last line.
	result := lastStorePath(out)
	if result == "" {
		return nil, fmt.Errorf("evaluating %s gave no result", projectFile)
	}
	m, err := readManifest(result)
	if err != nil {
		return nil, err
	}
	return m, writeJSON(cache, cached{Key: key, Result: result})
}

// hostAccess is what sandbox.nix asks for beyond the inside of the sandbox,
// as approved and stored.
type hostAccess struct {
	Binds     []bind   `json:"binds"`
	HostPorts []string `json:"hostPorts"`
}

func (h hostAccess) String() string {
	var lines []string
	for _, b := range h.Binds {
		dst := ""
		if b.Dst != "" {
			dst = " at " + b.Dst
		}
		mode := map[string]string{"ro": "read-only", "rw": "read-write"}[b.Mode]
		if b.Optional {
			mode += ", optional"
		}
		lines = append(lines, fmt.Sprintf("  bind %s%s (%s)", b.Src, dst, mode))
	}
	for _, p := range h.HostPorts {
		lines = append(lines, "  host port "+p)
	}
	return strings.Join(lines, "\n")
}

// approveProject asks for a yes on the terminal to binds and host ports
// from sandbox.nix, again whenever they change: the sandbox can edit
// sandbox.nix, so its say-so alone must never widen the next sandbox. The
// approval is stored in the volume dir, out of the sandbox's reach.
func (l *launcher) approveProject(m *manifest) error {
	access := hostAccess{Binds: m.Binds, HostPorts: m.HostPorts}
	if len(access.Binds) == 0 && len(access.HostPorts) == 0 {
		return nil
	}
	approved := filepath.Join(l.volumeDir, "project-approved.json")
	want, err := json.Marshal(access, json.Deterministic(true))
	if err != nil {
		return err
	}
	if have, err := os.ReadFile(approved); err == nil && bytes.Equal(bytes.TrimSpace(have), want) {
		return nil
	}
	projectFile := filepath.Join(l.project, projectFileName)
	t, err := openTTY()
	if err != nil {
		return fmt.Errorf("%s asks for host access that isn't approved yet; start the sandbox from a terminal to approve it", projectFile)
	}
	defer t.Close()
	if !t.confirm(fmt.Sprintf("sandbox: %s asks for host access:\n%s\nAllow? [y/N] ", projectFile, access)) {
		return errors.New("host access not approved, not starting")
	}
	return writeJSON(approved, access)
}

// applyProject is the profile with sandbox.nix's additions: its binds on
// top, and its Claude config (already merged with the profile's by
// project.nix) in place of the profile's - none without one in the profile.
func applyProject(p profile, m *manifest) profile {
	p.Binds = slices.Concat(p.Binds, m.Binds)
	if p.ClaudeDir != "" && m.ClaudeDir != "" {
		p.ClaudeDir = m.ClaudeDir
	}
	return p
}

// runCapturing runs argv with no stdin, its stdout captured and its stderr
// the launcher's. A signal to the launcher interrupts it.
func (l *launcher) runCapturing(ctx context.Context, argv ...string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", errors.New("interrupted")
	}
	return string(out), err
}
