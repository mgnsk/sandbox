package launcher

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
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

// The project's flake, whose default dev shell carries the sandbox's
// configuration (sandbox.lib.mkShell), and its lock.
const (
	projectFileName = "flake.nix"
	lockFileName    = "flake.lock"
)

// TODO: drop once projects have moved their sandbox.nix to the flake: the
// file the configuration was in before, which is now only warned about.
const oldProjectFileName = "sandbox.nix"

// The largest flake.nix, flake.lock, .sandbox.yml and manifest read.
const (
	maxProjectFile = 16 << 20
	maxManifest    = 1 << 20
)

// manifest is what project.nix makes of the flake's sandbox module.
type manifest struct {
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
		return nil, fmt.Errorf("can't read the %s evaluation: %w", projectFileName, err)
	}
	m := &manifest{}
	if err := json.Unmarshal(data, m, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("bad %s evaluation %s: %w", projectFileName, path, err)
	}
	if err := m.check(); err != nil {
		return nil, fmt.Errorf("bad %s evaluation %s: %w", projectFileName, path, err)
	}
	return m, nil
}

func (m *manifest) check() error {
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

// readProjectFile reads a project file's bytes, for the cache key. Not
// through a symlink, which would have the launcher read a host file of the
// sandbox's choosing.
func readProjectFile(path string) ([]byte, error) {
	return readRegularFile(path, maxProjectFile)
}

// readLockFile is flake.lock's bytes, or nil without one.
func readLockFile(path string) ([]byte, error) {
	if !lexists(path) {
		return nil, nil
	}
	return readProjectFile(path)
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

// projectManifest is the manifest of the flake's sandbox module, from the
// cache while flake.nix, flake.lock and the sandbox's own config are
// unchanged. Files flake.nix imports aren't tracked; --reload picks them
// up.
func (l *launcher) projectManifest(ctx context.Context) (*manifest, error) {
	projectFile := filepath.Join(l.project, projectFileName)
	content, err := readProjectFile(projectFile)
	if err != nil {
		return nil, err
	}
	lock, err := readLockFile(filepath.Join(l.project, lockFileName))
	if err != nil {
		return nil, err
	}
	key := cacheKey(realpath(l.configPath), content, lock)
	cache := filepath.Join(l.volumeDir, "project.json")
	if !l.opts.Reload {
		if out := readCache(cache, key); out != "" {
			return readManifest(out)
		}
	}
	// Evaluated with nix inside a sandbox of the project, without its
	// config - and without guards, tokens or host ports: what evaluates
	// there is the project's code, and needs none.
	fmt.Fprintf(os.Stderr, "sandbox: evaluating %s\n", projectFile)
	out, err := l.runCapturing(ctx,
		l.self, "launch", "--config", l.configPath, "--eval", "--",
		"nix", "build", "--no-link", "--print-out-paths", "--file", l.cfg.Project.Eval,
		"--argstr", "nixpkgs", l.cfg.Project.Nixpkgs,
		"--argstr", "system", l.cfg.Project.System,
		"--argstr", "flake", l.project,
	)
	if err != nil {
		return nil, fmt.Errorf("evaluating %s: %w (flakes see only what git tracks: `git add` a new file; "+
			"--no-project-config starts without the flake)", projectFile, err)
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

// hostAccess is what a project's files ask for beyond the inside of the
// sandbox.
type hostAccess struct {
	Binds     []approvedBind `json:"binds,omitempty"`
	HostPorts []string       `json:"hostPorts,omitempty"`
	tokenCommands
	GitSigningKeyCommand string         `json:"gitSigningKeyCommand,omitempty"`
	Wayland              *waylandAccess `json:"wayland,omitempty"`
}

// items are the things h asks for, each as a hostAccess of its own: what
// the user approves, and what's stored, is each of them. So a start that
// uses only some of them - the user's own config has a token command, or
// turns a guard off - has nothing new to ask.
//
// The binds are one thing together: one may be there to cover part of
// another (read-only, in a read-write one), so having approved a list isn't
// having approved a part of it. A global a project takes off the Wayland
// allowlist is no item: that asks for less.
func (h hostAccess) items() []hostAccess {
	var items []hostAccess
	if len(h.Binds) > 0 {
		items = append(items, hostAccess{Binds: h.Binds})
	}
	for _, p := range h.HostPorts {
		items = append(items, hostAccess{HostPorts: []string{p}})
	}
	if c := h.GitHubTokenCommand; c != "" {
		items = append(items, hostAccess{tokenCommands: tokenCommands{GitHubTokenCommand: c}})
	}
	for _, host := range slices.Sorted(maps.Keys(h.ForgejoTokenCommands)) {
		one := map[string]string{host: h.ForgejoTokenCommands[host]}
		items = append(items, hostAccess{tokenCommands: tokenCommands{ForgejoTokenCommands: one}})
	}
	if c := h.ClaudeAPIKeyCommand; c != "" {
		items = append(items, hostAccess{tokenCommands: tokenCommands{ClaudeAPIKeyCommand: c}})
	}
	if c := h.GitSigningKeyCommand; c != "" {
		items = append(items, hostAccess{GitSigningKeyCommand: c})
	}
	if w := h.Wayland; w != nil {
		if w.Enable {
			items = append(items, hostAccess{Wayland: &waylandAccess{Enable: true}})
		}
		for _, name := range slices.Sorted(maps.Keys(w.Globals)) {
			if w.Globals[name] {
				items = append(items, hostAccess{Wayland: &waylandAccess{Globals: map[string]bool{name: true}}})
			}
		}
	}
	return items
}

// key is what an item is stored and looked up as.
func (h hostAccess) key() string {
	data, _ := json.Marshal(h, json.Deterministic(true))
	return string(data)
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

// applyProject reads the project's settings - its flake's sandbox module
// (committed) and .sandbox.yml (each user's, over it) - has the user
// approve what of them reaches the host, and returns the profile with them
// applied.
//
// For a token command, the user's own config's word counts first, then
// .sandbox.yml's, then the flake's; one that wouldn't run is not asked
// about.
func (l *launcher) applyProject(ctx context.Context, prof profile) (profile, projectSettings, error) {
	if l.opts.NoProjectConfig || l.opts.Eval {
		return prof, projectSettings{}, nil
	}
	local, err := readLocalConfig(l.project)
	if err != nil {
		return prof, projectSettings{}, err
	}
	if lexists(filepath.Join(l.project, oldProjectFileName)) {
		fmt.Fprintf(os.Stderr, "sandbox: %s is no longer read: its settings go in the flake, "+
			"as sandbox.lib.mkShell's `sandbox`\n", filepath.Join(l.project, oldProjectFileName))
	}
	m := &manifest{}
	if lexists(filepath.Join(l.project, projectFileName)) {
		if m, err = l.projectManifest(ctx); err != nil {
			return prof, projectSettings{}, err
		}
	}
	git := local.Git.over(m.git())
	binds, err := l.approvedBinds(m.Binds)
	if err != nil {
		return prof, projectSettings{}, err
	}
	// What the project asks for, whatever the user's config says...
	asked := hostAccess{Binds: binds, HostPorts: m.HostPorts, tokenCommands: local.tokenCommands.over(m.tokenCommands),
		GitSigningKeyCommand: git.SigningKeyCommand}
	// Not a project that only takes globals away.
	if m.Wayland.widens() {
		asked.Wayland = &m.Wayland
	}
	// ...and what of it this start uses.
	used := asked
	used.tokenCommands = asked.tokenCommands.without(prof.tokenCommands)
	if enable := l.cfg.Guards.Wayland.Enable; enable != nil && !*enable {
		used.Wayland = nil
	}
	if err := l.approve(asked, used); err != nil {
		return prof, projectSettings{}, err
	}
	prof.Binds = slices.Concat(prof.Binds, m.Binds)
	prof.tokenCommands = prof.tokenCommands.over(used.tokenCommands)
	if len(l.command) == 0 {
		l.command = m.Command
	}
	return prof, projectSettings{hostPorts: m.HostPorts, git: git, wayland: m.Wayland}, nil
}

// approve asks for a yes on the terminal to what a project's files ask of
// the host - binds, host ports, commands run there - unless all that this
// start uses of it is approved already: the sandbox can edit those files,
// so their say-so alone must never widen the next sandbox, nor run anything
// on the host.
//
// The approvals are stored item by item (see hostAccess.items) in the
// volume dir, out of the sandbox's reach - those of what the project still
// asks for: one for something it has dropped is forgotten, so that it's
// asked about again should it come back.
func (l *launcher) approve(asked, used hostAccess) error {
	path := filepath.Join(l.volumeDir, "project-approved.json")
	have, _ := os.ReadFile(path)
	var stored []hostAccess
	_ = json.Unmarshal(have, &stored) // Unreadable: nothing is approved.
	approved := map[string]bool{}
	for _, item := range stored {
		approved[item.key()] = true
	}
	if slices.ContainsFunc(used.items(), func(item hostAccess) bool { return !approved[item.key()] }) {
		if err := l.confirmAccess(used); err != nil {
			return err
		}
		for _, item := range used.items() {
			approved[item.key()] = true
		}
	}
	var keep []hostAccess
	for _, item := range asked.items() {
		if approved[item.key()] {
			keep = append(keep, item)
		}
	}
	if len(keep) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if want, err := json.Marshal(keep, json.Deterministic(true)); err == nil && bytes.Equal(bytes.TrimSpace(have), want) {
		return nil
	}
	return writeJSON(path, keep)
}

// confirmAccess has the user say yes on the terminal to access, shown
// whole.
func (l *launcher) confirmAccess(access hostAccess) error {
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
	if !t.confirm(popup.CleanText(fmt.Sprintf("sandbox: %s asks for host access:\n%s\n"+
		"Read it before allowing: the commands run on this host as you, outside the sandbox.\n"+
		"This is asked once, and again only for something new. Allow? [y/N] ", from, access))) {
		return errors.New("host access not approved, not starting")
	}
	return nil
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
