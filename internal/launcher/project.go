package launcher

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/mgnsk/sandbox/internal/popup"
)

// The largest .sandbox.yml read.
const maxProjectFile = 16 << 20

// plainText says whether s is printable but for line breaks and tabs.
// What a project's file has run on the host is shown on the terminal for
// approval first: an escape sequence or a carriage return in it could show
// something else than what's then run.
func plainText(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool {
		return r != '\n' && r != '\t' && !unicode.IsPrint(r)
	})
}

// readProjectFile reads a file of the project's. Not through a symlink,
// which would have the launcher read a host file of the sandbox's choosing.
func readProjectFile(path string) ([]byte, error) {
	return readRegularFile(path, maxProjectFile)
}

// hostAccess is what a project's .sandbox.yml asks to run on the host: the
// token commands and git's signing key command.
type hostAccess struct {
	tokenCommands
	GitSigningKeyCommand string `json:"gitSigningKeyCommand,omitempty"`
}

// items are the commands h asks for, each as a hostAccess of its own: what
// the user approves, and what's stored, is each of them. So a start that
// uses only some of them - the user's own config has a token command - has
// nothing new to ask.
func (h hostAccess) items() []hostAccess {
	var items []hostAccess
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
	return items
}

// key is what an item is stored and looked up as.
func (h hostAccess) key() string {
	data, _ := json.Marshal(h, json.Deterministic(true))
	return string(data)
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
	return strings.Join(lines, "\n")
}

// applyProject reads the project's .sandbox.yml - each user's own, for
// that project - has the user approve the commands of it that run on the
// host, and returns the profile with them applied, and git's settings
// inside: .sandbox.yml's over the user's config's.
//
// For a token command, the user's own config's word counts first; one of
// .sandbox.yml's it overrides is not asked about.
func (l *launcher) applyProject(prof profile) (profile, gitSettings, error) {
	base := gitSettings{FromHost: &l.cfg.Git.FromHost}
	if l.opts.NoProjectConfig {
		return prof, base, nil
	}
	local, err := readLocalConfig(l.project)
	if err != nil {
		return prof, base, err
	}
	git := local.Git.over(base)
	// What the file asks for, whatever the user's config says...
	asked := hostAccess{tokenCommands: local.tokenCommands, GitSigningKeyCommand: git.SigningKeyCommand}
	// ...and what of it this start uses.
	used := asked
	used.tokenCommands = asked.tokenCommands.without(prof.tokenCommands)
	if err := l.approve(asked, used); err != nil {
		return prof, base, err
	}
	prof.tokenCommands = prof.tokenCommands.over(used.tokenCommands)
	return prof, git, nil
}

// approve asks for a yes on the terminal to the commands .sandbox.yml has
// run on the host, unless all that this start uses of them is approved
// already: the sandbox can edit the file, so its say-so alone must never
// run anything on the host.
//
// The approvals are stored item by item (see hostAccess.items) in the
// volume dir, out of the sandbox's reach - those of what the file still
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
	from := filepath.Join(l.project, localConfigFileName)
	t, err := openTTY()
	if err != nil {
		return fmt.Errorf("%s asks to run commands on the host that aren't approved yet; start the sandbox from a terminal to approve them", from)
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
