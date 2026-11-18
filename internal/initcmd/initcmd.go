// Package initcmd is sandbox-init, run by the sandbox launcher inside the
// sandbox, before the login shell:
//
//	sandbox-init NIX_PROFILE HM_GENERATION COMMAND...
//
// It links the host's nix profile and current home-manager generation into
// the per-project home volume (either may be empty for none), and Claude
// Code's marketplace list to the managed one, then execs COMMAND.
//
// Each link points at the generation's store path, so a home-manager switch
// on the host takes effect at the next start of a sandbox of the project.
// Files added since the last start get linked here, and links into any other
// generation get removed - nothing to list by hand.
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
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/mgnsk/sandbox/internal/cover"
)

// Where the launcher mounts the profile's managed Claude Code config.
const managedClaudeDir = "/etc/claude-code"

func warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sandbox-init: "+format+"\n", a...)
}

// strerror is err's errno as the C library words it ("Not a directory"),
// or err itself for anything else.
func strerror(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s := errno.Error()
		if s != "" {
			return strings.ToUpper(s[:1]) + s[1:]
		}
	}
	return err.Error()
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&fs.ModeSymlink != 0
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
	if _, err := os.Lstat(tmp); err == nil {
		if err := syscall.Unlink(tmp); err != nil {
			return &fs.PathError{Op: "unlink", Path: tmp, Err: err}
		}
	}
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// unescapeMountinfo undoes mountinfo's octal escapes of space, tab, newline
// and backslash.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountPoints lists the mounts over the volume under home - not its own,
// and may be whole repos.
func mountPoints(home string) map[string]bool {
	mounts := map[string]bool{}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return mounts
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 {
			mount := unescapeMountinfo(fields[4])
			if strings.HasPrefix(mount, home+"/") {
				mounts[mount] = true
			}
		}
	}
	return mounts
}

// walkLinks calls fn for every symlink under home, not descending into skip
// or through links. Unreadable directories are passed over.
func walkLinks(home string, skip map[string]bool, fn func(path string)) {
	_ = filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if path == home {
			return nil
		}
		if err != nil {
			return nil
		}
		if skip[path] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			fn(path)
		}
		return nil
	})
}

// generationFiles lists the paths relative to homeFiles of every file or link
// in it, not descending through links, sorted.
func generationFiles(homeFiles string) []string {
	var out []string
	_ = filepath.WalkDir(homeFiles, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(homeFiles, path)
		if err == nil {
			out = append(out, rel)
		}
		return nil
	})
	slices.Sort(out)
	return out
}

// realpath is path with its links resolved, or just absolute if it doesn't
// exist.
func realpath(path string) string {
	abs, _ := filepath.Abs(path)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
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

	homeFiles := realpath(filepath.Join(generation, "home-files"))
	storeDir := filepath.Dir(homeFiles)

	// Only a link this program made; anything else is the volume's own.
	// Matched by name, since an old generation may be garbage-collected.
	var stale []string
	walkLinks(home, mountPoints(home), func(link string) {
		target, err := os.Readlink(link)
		if err != nil {
			return
		}
		rest, ok := strings.CutPrefix(target, storeDir+"/")
		if !ok {
			return
		}
		name, _, _ := strings.Cut(rest, "/")
		if strings.HasSuffix(name, "-home-manager-files") &&
			!strings.HasPrefix(target, homeFiles+"/") {
			stale = append(stale, link)
		}
	})
	for _, link := range stale {
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
		if isDir(dst) && !isSymlink(dst) {
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
			warn("not linking ~/%s: %s", rel, strerror(err))
		}
	}
	return nil
}

// linkKnownMarketplaces points Claude Code's marketplace list at the managed
// one, or drops a link left from a configuration that had one.
func linkKnownMarketplaces(home, managed string) error {
	link := filepath.Join(home, ".claude/plugins/known_marketplaces.json")
	target := filepath.Join(managed, "known_marketplaces.json")
	switch {
	case exists(target):
		if linksTo(link, target) {
			return nil
		}
		err := os.MkdirAll(filepath.Dir(link), 0o777)
		if err == nil {
			err = relink(link, target)
		}
		if err != nil {
			warn("not linking %s: %s", link, strerror(err))
		}
	case linksTo(link, target):
		return os.Remove(link)
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
		warn("not writing %s: %s", ghConfig, strerror(err))
	}
}

// Main runs sandbox-init with argv; it returns only on failure.
func Main(argv []string) int {
	if len(argv) < 4 {
		warn("usage: sandbox-init NIX_PROFILE HM_GENERATION COMMAND...")
		return 2
	}
	nixProfile, generation, command := argv[1], argv[2], argv[3:]
	home := os.Getenv("HOME")
	if home == "" {
		warn("HOME is not set")
		return 1
	}

	if nixProfile != "" {
		if err := relink(filepath.Join(home, ".nix-profile"), nixProfile); err != nil {
			warn("%v", err)
			return 1
		}
	}
	if generation != "" && isDir(generation) {
		if err := linkGeneration(home, generation); err != nil {
			warn("%v", err)
			return 1
		}
	}
	if err := linkKnownMarketplaces(home, managedClaudeDir); err != nil {
		warn("%v", err)
		return 1
	}
	writeGhConfig(home)

	return execvp(command)
}

// execvp replaces the process with command, looked up in $PATH.
func execvp(command []string) int {
	path, err := exec.LookPath(command[0])
	switch {
	case errors.Is(err, exec.ErrNotFound):
		warn("%s: command not found", command[0])
		return 127
	case err != nil && !errors.Is(err, exec.ErrDot):
		warn("%s: %s", command[0], strerror(err))
		return 126
	}
	cover.Flush()
	err = syscall.Exec(path, command, os.Environ())
	warn("%s: %s", command[0], strerror(err))
	return 126
}
