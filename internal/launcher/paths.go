package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	// should write: ssh keys and config, every sandbox's volume and
	// exchange dir, the gh token, an ssh agent socket, ...
	if strings.HasPrefix(cwd+"/", home+"/.") {
		return fmt.Errorf("refusing to run in %s, it is host state under $HOME", cwd)
	}
	return nil
}

// Directories a project must not be or contain: bound read-write, the
// project would lay the host's over what the sandbox has of its own there -
// in /tmp or the runtime dir, the sockets of the host's session (tmux, the
// session bus, an ssh agent, the launcher's own guards).
var systemDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run", "/nix", "/etc", "/proc", "/sys", "/dev"}

// checkSystem refuses a cwd that is or contains a system or temp
// directory, or is in the runtime dir, which is all host state.
func checkSystem(cwd, runtimeDir string) error {
	if within(cwd, runtimeDir) {
		return fmt.Errorf("refusing to run in %s, it is host state in $XDG_RUNTIME_DIR", cwd)
	}
	for _, dir := range append([]string{runtimeDir, os.TempDir()}, systemDirs...) {
		if dir = realpath(dir); within(dir, cwd) {
			return fmt.Errorf("refusing to run in %s, it contains %s", cwd, dir)
		}
	}
	return nil
}

// checkOutside refuses a cwd overlapping the state dir, which holds every
// sandbox's volume.
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
// config, which the sandbox can write. Only in a directory of the user's
// own, as git itself has it (safe.directory): a .git someone else left in
// /tmp would make all of /tmp the project of a sandbox started under it.
func projectRoot(cwd string) string {
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if exists(filepath.Join(dir, ".git")) && ownDir(dir) {
			return dir
		}
		if dir == "/" {
			return cwd
		}
	}
}

// ownDir says whether dir is the user's own.
func ownDir(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// volumeName is the per-project name: the path made flat, plus a hash so
// that flattening can't make two projects collide.
func volumeName(project string) string {
	digest := sha256.Sum256([]byte(project))
	return strings.ReplaceAll(project, "/", "_") + "-" + hex.EncodeToString(digest[:4])
}

// hostName is the host name inside: the project's directory name as a DNS
// label, so that a prompt or a window title says which project a shell is
// in. The sandbox has its own UTS namespace, and would otherwise show the
// name pasta gave its own.
func hostName(project string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return '-'
	}, filepath.Base(project))
	if len(name) > 63 {
		name = name[:63]
	}
	if name = strings.Trim(name, "-"); name == "" {
		return "sandbox"
	}
	return name
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

// isStoreObject says whether p is a store path itself, not a path in one:
// with nothing under it to resolve, O_NOFOLLOW is all it takes to read the
// object and nothing else.
func isStoreObject(p string) bool {
	return isStorePath(p) && filepath.Dir(p) == "/nix/store"
}

// readRegularFile reads the regular file at path, of up to limit bytes -
// not through a symlink at its last component, which would have the
// launcher read a host file of the sandbox's choosing.
func readRegularFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("can't read %s (it must be a regular file): %w", path, err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
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

// writeJSON writes value atomically into a directory only the host writes;
// through a file of its own, as another sandbox of the project may be
// starting too.
func writeJSON(path string, value any) error {
	data, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(append(data, '\n'))
	if err = errors.Join(err, tmp.Close()); err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
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
