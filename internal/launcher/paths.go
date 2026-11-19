package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// expand expands a leading ~ and $VAR/${VAR} references from vars in value;
// unknown variables are left as they are.
func expand(value string, vars map[string]string) string {
	if value == "~" || strings.HasPrefix(value, "~/") {
		value = "$HOME" + value[1:]
	}
	return os.Expand(value, func(name string) string {
		if v, ok := vars[name]; ok {
			return v
		}
		return "$" + name
	})
}

// realpath is path, absolute, with its symlinks resolved as far as it
// exists.
func realpath(path string) string {
	path, _ = filepath.Abs(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	dir, base := filepath.Split(path)
	if dir == path || base == "" {
		return path
	}
	return filepath.Join(realpath(filepath.Clean(dir)), base)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func lexists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// within says whether path is dir or under it.
func within(path, dir string) bool {
	return strings.HasPrefix(path+"/", strings.TrimRight(dir, "/")+"/")
}

// checkCwd refuses directories the read-write project bind must never
// cover.
func checkCwd(cwd, home string) error {
	// $PWD is bound read-write; in ~ (or above it) that would be the whole
	// host home over the volume.
	if within(home, cwd) {
		return fmt.Errorf("refusing to run in %s, it contains $HOME", cwd)
	}
	// The dot directories directly under ~ hold host state no sandbox
	// should write: ssh keys and config, every sandbox's volume, secrets and
	// exchange dir, the gh token, an ssh agent socket, ...
	if strings.HasPrefix(cwd+"/", home+"/.") {
		return fmt.Errorf("refusing to run in %s, it is host state under $HOME", cwd)
	}
	return nil
}

// checkOutside refuses a cwd overlapping the state dir, which holds every
// sandbox's volume and secrets.
func checkOutside(cwd, stateDir string) error {
	if within(cwd, stateDir) || within(stateDir, cwd) {
		return fmt.Errorf("refusing to run in %s, it overlaps the sandbox state dir %s", cwd, stateDir)
	}
	return nil
}

// projectRoot is the enclosing git work tree's top level (where .git is, as
// a directory or a worktree's file), or cwd itself outside one.
//
// Found by looking, not by running git: git on the host reads the repo's
// config, which the sandbox can write.
func projectRoot(cwd string) string {
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if exists(filepath.Join(dir, ".git")) {
			return dir
		}
		if dir == "/" {
			return cwd
		}
	}
}

// volumeName is the per-project name: the path made flat, plus a hash so
// that flattening can't make two projects collide.
func volumeName(project string) string {
	digest := sha256.Sum256([]byte(project))
	return strings.ReplaceAll(project, "/", "_") + "-" + hex.EncodeToString(digest[:4])
}

const nixBase32 = "0123456789abcdfghijklmnpqrsvwxyz"

// isStorePath says whether p is a path in the nix store, in its canonical
// form: no "..", nothing to resolve to elsewhere.
func isStorePath(p string) bool {
	rest, ok := strings.CutPrefix(p, "/nix/store/")
	name, _, _ := strings.Cut(rest, "/")
	hash, _, named := strings.Cut(name, "-")
	return ok && named && len(hash) == 32 && filepath.Clean(p) == p &&
		!strings.ContainsFunc(hash, func(r rune) bool { return !strings.ContainsRune(nixBase32, r) })
}

// lastStorePath is the last line of out that's a store path: a build's
// result, after whatever a shell's startup files printed.
func lastStorePath(out string) string {
	last := ""
	for line := range strings.Lines(out) {
		if line = strings.TrimSpace(line); isStorePath(line) {
			last = line
		}
	}
	return last
}

// writeJSON writes value atomically into a directory only the host writes.
func writeJSON(path string, value any) error {
	data, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cacheKey is a hash of what a cached result was made from.
func cacheKey(parts ...any) string {
	data, _ := json.Marshal(parts)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// xdgDir is $env, or fallback under home when that's unset.
func xdgDir(env, home, fallback string) string {
	if dir := os.Getenv(env); dir != "" {
		return dir
	}
	return filepath.Join(home, fallback)
}
