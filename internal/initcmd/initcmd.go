// Package initcmd is sandbox-bin init, run by the sandbox launcher inside
// the sandbox, before the login shell:
//
//	sandbox-bin init NIX_PROFILE HM_GENERATION COMMAND...
//
// It links the host's nix profile and current home-manager generation into
// the per-project home volume, and Claude Code's marketplace list to the
// managed one, starts the router the API
// guards are reached through (internal/router) when a guard is on, then
// execs COMMAND.
//
// Each link points at the generation's store path, so a home-manager switch
// on the host takes effect at the next start of a sandbox of the project.
// Files added since the last start get linked here, and links into any other
// generation get removed - nothing to list by hand.
//
// An empty NIX_PROFILE or HM_GENERATION removes the links an earlier start
// made for it: a volume is shared by every sandbox command the project is
// started with, and one configured without the profiles - the flake's
// default package - must not show what a home-manager one linked.
//
// Run in here rather than on the host, since the volume is the sandbox's to
// rearrange: a symlink planted in it would point host-side writes at real
// host paths, while in here it only reaches what the sandbox can already
// write.
package initcmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mgnsk/sandbox/internal/router"
)

// Where the launcher mounts the profile's managed Claude Code config.
const managedClaudeDir = "/etc/claude-code"

func warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sandbox-bin init: "+format+"\n", a...)
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func linksTo(path, target string) bool {
	got, err := os.Readlink(path)
	return err == nil && got == target
}

// relink makes path a symlink to target, replacing a file or link there.
func relink(path, target string) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".sandbox-init")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// mountinfoUnescape undoes /proc/self/mountinfo's escapes.
var mountinfoUnescape = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)

// mountPoints lists the mounts over the volume under home - not its own,
// and may be whole repos.
func mountPoints(home string) map[string]bool {
	mounts := map[string]bool{}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return mounts
	}
	for line := range strings.Lines(string(data)) {
		if fields := strings.Fields(line); len(fields) > 4 {
			if mount := mountinfoUnescape.Replace(fields[4]); strings.HasPrefix(mount, home+"/") {
				mounts[mount] = true
			}
		}
	}
	return mounts
}

// staleLinks lists the links under home into the files of a generation in
// storeDir other than keep (empty: of any generation), not descending into
// skip. Only a link this program made;
// anything else is the volume's own. Matched by name, since an old
// generation may be garbage-collected.
func staleLinks(home, storeDir, keep string, skip map[string]bool) []string {
	var stale []string
	_ = filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil, path == home:
			return nil
		case skip[path] && d.IsDir():
			return filepath.SkipDir
		case d.Type()&fs.ModeSymlink == 0:
			return nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return nil
		}
		rest, ok := strings.CutPrefix(target, storeDir+"/")
		name, _, _ := strings.Cut(rest, "/")
		if ok && strings.HasSuffix(name, "-home-manager-files") && (keep == "" || !strings.HasPrefix(target, keep+"/")) {
			stale = append(stale, path)
		}
		return nil
	})
	return stale
}

// generationFiles lists the paths relative to homeFiles of every file or
// link in it, not descending through links, in order.
func generationFiles(homeFiles string) []string {
	var out []string
	_ = filepath.WalkDir(homeFiles, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(homeFiles, path)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// linkGeneration links every file of generation's home-files into home.
func linkGeneration(home, generation string) error {
	// For tools that diff a build against the current generation.
	profiles := filepath.Join(home, ".local/state/nix/profiles")
	if err := os.MkdirAll(profiles, 0o777); err != nil {
		return err
	}
	if err := relink(filepath.Join(profiles, "home-manager"), generation); err != nil {
		return err
	}
	homeFiles, err := filepath.EvalSymlinks(filepath.Join(generation, "home-files"))
	if err != nil {
		return err
	}
	for _, link := range staleLinks(home, filepath.Dir(homeFiles), homeFiles, mountPoints(home)) {
		if err := os.Remove(link); err != nil {
			return err
		}
	}
	for _, rel := range generationFiles(homeFiles) {
		dst := filepath.Join(home, rel)
		src := filepath.Join(homeFiles, rel)
		if linksTo(dst, src) {
			continue
		}
		if fi, err := os.Lstat(dst); err == nil && fi.IsDir() {
			if err := syscall.Rmdir(dst); err != nil {
				warn("not linking ~/%s, a non-empty directory is in the way", rel)
				continue
			}
		}
		err := os.MkdirAll(filepath.Dir(dst), 0o777)
		if err == nil {
			err = relink(dst, src)
		}
		if err != nil {
			warn("not linking ~/%s: %v", rel, err)
		}
	}
	return nil
}

// unlinkGeneration removes what linkGeneration made for any generation.
func unlinkGeneration(home string) error {
	// Made first by linkGeneration, so without it there is nothing linked;
	// it also tells where the store is.
	profile := filepath.Join(home, ".local/state/nix/profiles/home-manager")
	generation, err := os.Readlink(profile)
	if err != nil {
		return nil
	}
	for _, link := range staleLinks(home, filepath.Dir(generation), "", mountPoints(home)) {
		if err := os.Remove(link); err != nil {
			return err
		}
	}
	return os.Remove(profile)
}

// unlinkNixProfile removes a ~/.nix-profile link to the host's profile. One
// into the volume is a profile made inside, and stays.
func unlinkNixProfile(home string) error {
	link := filepath.Join(home, ".nix-profile")
	target, err := os.Readlink(link)
	if err != nil || !filepath.IsAbs(target) || strings.HasPrefix(target, home+"/") {
		return nil
	}
	return os.Remove(link)
}

// linkKnownMarketplaces points Claude Code's marketplace list at the managed
// one, or drops a link left from a configuration that had one.
func linkKnownMarketplaces(home, managed string) error {
	link := filepath.Join(home, ".claude/plugins/known_marketplaces.json")
	target := filepath.Join(managed, "known_marketplaces.json")
	if _, err := os.Stat(target); err != nil {
		if linksTo(link, target) {
			return os.Remove(link)
		}
		return nil
	}
	if linksTo(link, target) {
		return nil
	}
	err := os.MkdirAll(filepath.Dir(link), 0o777)
	if err == nil {
		err = relink(link, target)
	}
	if err != nil {
		warn("not linking %s: %v", link, err)
	}
	return nil
}

// writeGhConfig: `gh pr checkout` of a PR from a fork with no matching
// remote builds the fetch URL from git_protocol; https would only carry the
// placeholder token, ssh goes through ssh-agent-guard. Written only into a
// fresh volume - an existing gh config there is the sandbox's own.
func writeGhConfig(home string) {
	ghConfig := filepath.Join(home, ".config/gh/config.yml")
	if _, err := os.Lstat(ghConfig); err == nil {
		return
	}
	err := os.MkdirAll(filepath.Dir(ghConfig), 0o777)
	if err == nil {
		err = os.WriteFile(ghConfig, []byte("git_protocol: ssh\n"), 0o666)
	}
	if err != nil {
		warn("not writing %s: %v", ghConfig, err)
	}
}

// Run links what there is to link, then execs command; it returns only on
// failure, with the exit status.
func Run(nixProfile, generation string, command []string) int {
	home := os.Getenv("HOME")
	if home == "" {
		warn("HOME is not set")
		return 1
	}
	var err error
	switch {
	case nixProfile == "":
		err = unlinkNixProfile(home)
	default:
		err = relink(filepath.Join(home, ".nix-profile"), nixProfile)
	}
	if err != nil {
		warn("%v", err)
		return 1
	}
	switch {
	case generation == "":
		err = unlinkGeneration(home)
	// One that is gone is skipped.
	case isDir(generation):
		err = linkGeneration(home, generation)
	}
	if err != nil {
		warn("%v", err)
		return 1
	}
	if err := linkKnownMarketplaces(home, managedClaudeDir); err != nil {
		warn("%v", err)
		return 1
	}
	writeGhConfig(home)
	warnStoredLogins(home)
	env, err := router.Start(os.Environ())
	if err != nil {
		warn("%v", err)
		return 1
	}

	path, err := exec.LookPath(command[0])
	if errors.Is(err, exec.ErrNotFound) {
		warn("%s: command not found", command[0])
		return 127
	}
	if err == nil {
		err = syscall.Exec(path, command, env)
	}
	warn("%v", err)
	return 126
}
