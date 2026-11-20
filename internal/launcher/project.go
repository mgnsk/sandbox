package launcher

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/mgnsk/sandbox/internal/popup"
	"github.com/mgnsk/sandbox/internal/waylandguard"
)

const projectFileName = "sandbox.nix"

// The largest sandbox.nix, .sandbox.yml and manifest read.
const (
	maxProjectFile = 16 << 20
	maxManifest    = 1 << 20
)

// manifest is what project.nix makes of sandbox.nix.
type manifest struct {
	ClaudeDir string   `json:"claudeDir"`
	Binds     []bind   `json:"binds"`
	HostPorts []string `json:"hostPorts"`
	Command   []string `json:"command"`
	// Run on the host once approved.
	tokenCommands
	// Git's signing key, or a command printing it (approved like the
	// token commands); a user's .sandbox.yml wins.
	GitSigningKey        string `json:"gitSigningKey"`
	GitSigningKeyCommand string `json:"gitSigningKeyCommand"`
	GitFromHost          bool   `json:"gitFromHost"`
	// Windows on the host's Wayland display, and the project's changes to
	// the allowlist of globals (see guards.wayland).
	Wayland waylandAccess `json:"wayland"`
}

// waylandAccess is what a project asks of the Wayland guard.
type waylandAccess struct {
	Enable  bool            `json:"enable"`
	Globals map[string]bool `json:"globals,omitempty"`
}

// widens says whether w asks for more than the user's own config gives:
// the display itself, or a global on top of the allowlist.
func (w waylandAccess) widens() bool {
	return w.Enable || slices.Contains(slices.Collect(maps.Values(w.Globals)), true)
}

// readManifest reads a manifest. It comes out of a sandbox, so it's read
// strictly and every field is checked before the launcher uses it.
func readManifest(path string) (*manifest, error) {
	data, err := readRegularFile(path, maxManifest)
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
	if m.ClaudeDir != "" && !isStoreObject(m.ClaudeDir) {
		return errors.New("claudeDir is not a store path")
	}
	for _, b := range m.Binds {
		if b.Src == "" || b.Mode != "ro" && b.Mode != "rw" || !plainLine(b.Src) || !plainLine(b.Dst) {
			return fmt.Errorf("bad bind %q", fmt.Sprintf("%+v", b))
		}
	}
	if _, _, err := parseHostPorts(m.HostPorts); err != nil {
		return err
	}
	if m.Command != nil && len(m.Command) == 0 {
		return errors.New("empty command")
	}
	m.GitSigningKeyCommand = strings.TrimSpace(m.GitSigningKeyCommand)
	if err := errors.Join(m.tokenCommands.check(), m.git().check()); err != nil {
		return err
	}
	return waylandguard.CheckGlobals(m.Wayland.Globals)
}

// git is what m says of git inside.
func (m *manifest) git() gitSettings {
	return gitSettings{SigningKey: m.GitSigningKey, SigningKeyCommand: m.GitSigningKeyCommand, FromHost: &m.GitFromHost}
}

// plainText says whether s is printable but for line breaks and tabs.
// What a project has run on the host, or bound in, is shown on the terminal
// for approval first: an escape sequence or a carriage return in it could
// show something else than what's then run.
func plainText(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool {
		return r != '\n' && r != '\t' && !unicode.IsPrint(r)
	})
}

// plainLine is plainText on one line.
func plainLine(s string) bool {
	return plainText(s) && !strings.ContainsAny(s, "\n\t")
}

// readProjectFile reads sandbox.nix's bytes, for the cache key. Not through
// a symlink, which would have the launcher read a host file of the
// sandbox's choosing.
func readProjectFile(path string) ([]byte, error) {
	return readRegularFile(path, maxProjectFile)
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
	if err != nil || json.Unmarshal(data, &c) != nil || c.Key != key || !isStoreObject(c.Result) || !lexists(c.Result) {
		return ""
	}
	return c.Result
}

// projectManifest is sandbox.nix's manifest, from the cache while
// sandbox.nix, the sandbox's own config and the profile's Claude config are
// unchanged. Files sandbox.nix imports aren't tracked; --reload picks them
// up.
//
// claudeKey says Claude Code inside runs on an API key from .sandbox.yml,
// which the managed settings sandbox.nix's evaluation builds must know: the
// launcher never edits what comes out of it.
func (l *launcher) projectManifest(ctx context.Context, base string, claudeKey bool) (*manifest, error) {
	projectFile := filepath.Join(l.project, projectFileName)
	content, err := readProjectFile(projectFile)
	if err != nil {
		return nil, err
	}
	key := cacheKey(realpath(l.configPath), base, content, claudeKey)
	cache := filepath.Join(l.volumeDir, "project.json")
	if !l.opts.Reload {
		if out := readCache(cache, key); out != "" {
			// Evaluated again when its Claude config is gone from the
			// store: linked in, a missing one would go unnoticed.
			if m, err := readManifest(out); err != nil || m.ClaudeDir == "" || lexists(m.ClaudeDir) {
				return m, err
			}
		}
	}
	// Evaluated with nix inside a sandbox of the project, without its
	// sandbox.nix - and without guards, tokens or host ports: what
	// evaluates there is the project's code, and needs none.
	fmt.Fprintf(os.Stderr, "sandbox: evaluating %s\n", projectFile)
	argv := []string{
		l.self, "launch", "--config", l.configPath, "--eval", "--",
		"nix", "build", "--no-link", "--print-out-paths", "--file", l.cfg.Project.Eval,
		"--argstr", "nixpkgs", l.cfg.Project.Nixpkgs,
		"--argstr", "system", l.cfg.Project.System,
		"--argstr", "file", projectFile,
		"--argstr", "base", base,
	}
	if claudeKey {
		argv = append(argv, "--argstr", "claudeApiKey", "1")
	}
	out, err := l.runCapturing(ctx, argv...)
	if err != nil {
		return nil, fmt.Errorf("evaluating %s: %w", projectFile, err)
	}
	// The login shell's startup files may print too; the build's output is
	// the last line. Whatever ran in there chose it: only a store object
	// itself is read, never a path under one, which may lead anywhere.
	result := lastStorePath(out)
	if !isStoreObject(result) {
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
	Binds     []approvedBind `json:"binds"`
	HostPorts []string       `json:"hostPorts"`
	// Left out when empty, so approvals from before these existed still
	// match.
	tokenCommands
	GitSigningKeyCommand string         `json:"gitSigningKeyCommand,omitempty"`
	Wayland              *waylandAccess `json:"wayland,omitempty"`
}

func (h hostAccess) empty() bool {
	return len(h.Binds) == 0 && len(h.HostPorts) == 0 && !h.commands() && h.Wayland == nil
}

// commands says whether h has anything run on the host.
func (h hostAccess) commands() bool {
	return !h.tokenCommands.empty() || h.GitSigningKeyCommand != ""
}

// approvedBind is a bind as approved: with what its source resolved to
// when that's another path, so that a link aimed elsewhere since is asked
// about again.
type approvedBind struct {
	bind
	Resolved string `json:"resolved,omitempty"`
}

// String is what the user reads before saying yes. A command's further
// lines stay indented under it, so none of them reads as a line of the
// launcher's own.
func (h hostAccess) String() string {
	var lines []string
	command := func(what, c string) {
		lines = append(lines, "  run on this host at each start, for "+what+":\n    "+
			strings.ReplaceAll(c, "\n", "\n    "))
	}
	for _, b := range h.Binds {
		src := b.Src
		if b.Resolved != "" {
			src += " -> " + b.Resolved
		}
		dst := ""
		if b.Dst != "" {
			dst = " at " + b.Dst
		}
		mode := map[string]string{"ro": "read-only", "rw": "read-write"}[b.Mode]
		if b.Optional {
			mode += ", optional"
		}
		lines = append(lines, fmt.Sprintf("  bind %s%s (%s)", src, dst, mode))
	}
	for _, p := range h.HostPorts {
		lines = append(lines, "  host port "+p)
	}
	if h.GitHubTokenCommand != "" {
		command("the GitHub token", h.GitHubTokenCommand)
	}
	for _, host := range slices.Sorted(maps.Keys(h.ForgejoTokenCommands)) {
		command("the "+host+" token", h.ForgejoTokenCommands[host])
	}
	if h.ClaudeAPIKeyCommand != "" {
		command("Claude Code's API key", h.ClaudeAPIKeyCommand)
	}
	if h.GitSigningKeyCommand != "" {
		command("git's signing key", h.GitSigningKeyCommand)
	}
	if w := h.Wayland; w != nil {
		if w.Enable {
			lines = append(lines, "  windows on this host's Wayland display")
		}
		for _, name := range slices.Sorted(maps.Keys(w.Globals)) {
			change := "without"
			if w.Globals[name] {
				change = "with"
			}
			lines = append(lines, fmt.Sprintf("  Wayland clients inside %s the global %s", change, name))
		}
	}
	return strings.Join(lines, "\n")
}

// projectSettings is what a project's own files ask for beyond the profile
// they're applied to.
type projectSettings struct {
	hostPorts []string
	git       gitSettings
	wayland   waylandAccess
}

// applyProject reads the project's settings - sandbox.nix (committed) and
// .sandbox.yml (each user's, over it) - has the user approve what of them
// reaches the host, and returns the profile with them applied.
//
// For a token command, the user's own config's word counts first, then
// .sandbox.yml's, then sandbox.nix's; one that wouldn't run is not asked
// about.
func (l *launcher) applyProject(ctx context.Context, prof profile) (profile, projectSettings, error) {
	if l.opts.NoProjectConfig || l.opts.Eval {
		return prof, projectSettings{}, nil
	}
	local, err := readLocalConfig(l.project)
	if err != nil {
		return prof, projectSettings{}, err
	}
	m := &manifest{}
	if lexists(filepath.Join(l.project, projectFileName)) {
		claudeKey := local.ClaudeAPIKeyCommand != "" && prof.ClaudeAPIKeyCommand == ""
		if m, err = l.projectManifest(ctx, prof.ClaudeDir, claudeKey); err != nil {
			return prof, projectSettings{}, err
		}
	}
	git := local.Git.over(m.git())
	commands := local.tokenCommands.over(m.tokenCommands).without(prof.tokenCommands)
	// Without Claude Code in the sandbox (no managed config), no key.
	if prof.ClaudeDir == "" {
		commands.ClaudeAPIKeyCommand = ""
	}
	binds, err := l.approvedBinds(m.Binds)
	if err != nil {
		return prof, projectSettings{}, err
	}
	access := hostAccess{Binds: binds, HostPorts: m.HostPorts, tokenCommands: commands, GitSigningKeyCommand: git.SigningKeyCommand}
	// Not when the user's own config turns the guard off, nor for a
	// project that only takes globals away.
	if enable := l.cfg.Guards.Wayland.Enable; m.Wayland.widens() && (enable == nil || *enable) {
		access.Wayland = &m.Wayland
	}
	if err := l.approve(access); err != nil {
		return prof, projectSettings{}, err
	}
	prof = withManifest(prof, m)
	prof.tokenCommands = prof.tokenCommands.over(commands)
	if len(l.command) == 0 {
		l.command = m.Command
	}
	return prof, projectSettings{hostPorts: m.HostPorts, git: git, wayland: m.Wayland}, nil
}

// approve asks for a yes on the terminal to what a project's files ask of
// the host - binds, host ports, commands run there - again whenever it
// changes: the sandbox can edit those files, so their say-so alone must
// never widen the next sandbox, nor run anything on the host. The approval
// is stored in the volume dir, out of the sandbox's reach.
func (l *launcher) approve(access hostAccess) error {
	if access.empty() {
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
	from := filepath.Join(l.project, projectFileName)
	if access.commands() {
		from = fmt.Sprintf("%s (or %s)", from, localConfigFileName)
	}
	t, err := openTTY()
	if err != nil {
		return fmt.Errorf("%s asks for host access that isn't approved yet; start the sandbox from a terminal to approve it", from)
	}
	defer t.Close()
	// Checked when read, and cleaned here all the same: this prompt is
	// all that stands between the project and the host.
	if !t.confirm(popup.CleanText(strings.ReplaceAll(fmt.Sprintf("sandbox: %s asks for host access:\n%s\n"+
		"Read it before allowing: the commands run on this host as you, outside the sandbox.\n"+
		"This is asked once, and again only if it changes. Allow? [y/N] ", from, access), "\t", "    "))) {
		return errors.New("host access not approved, not starting")
	}
	return writeJSON(approved, access)
}

// approvedBinds are a project's binds as approved. A source the sandbox
// can write - in the project or the state dir - or reach through one of
// those is refused: approved once, it could be a link to anywhere at the
// next start.
func (l *launcher) approvedBinds(binds []bind) ([]approvedBind, error) {
	var out []approvedBind
	for _, b := range binds {
		src := expand(b.Src, l.vars)
		if !filepath.IsAbs(src) || b.Dst != "" && !filepath.IsAbs(expand(b.Dst, l.vars)) {
			return nil, fmt.Errorf("%s: bind %q: not an absolute path", projectFileName, b.Src)
		}
		a := approvedBind{bind: b}
		resolved := realpath(src)
		for _, dir := range []string{l.project, l.stateDir} {
			if within(resolved, dir) || within(filepath.Clean(src), dir) {
				return nil, fmt.Errorf("%s: bind %q is in %s, which the sandbox can write", projectFileName, b.Src, dir)
			}
		}
		if resolved != filepath.Clean(src) {
			a.Resolved = resolved
		}
		out = append(out, a)
	}
	return out, nil
}

// withManifest is the profile with sandbox.nix's additions: its binds on
// top, and its Claude config (already merged with the profile's by
// project.nix) in place of the profile's - none without one in the profile.
func withManifest(p profile, m *manifest) profile {
	p.Binds = slices.Concat(p.Binds, m.Binds)
	if p.ClaudeDir != "" && m.ClaudeDir != "" {
		p.ClaudeDir, p.claudeFromProject = m.ClaudeDir, true
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
