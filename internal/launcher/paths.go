package launcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// sandboxError is a reason not to start, printed as `sandbox: <message>`.
type sandboxError struct{ msg string }

func (e *sandboxError) Error() string { return e.msg }

func errorf(format string, a ...any) error {
	return &sandboxError{fmt.Sprintf(format, a...)}
}

var templateRE = regexp.MustCompile(`(?i)\$(?:(\$)|([_a-z][_a-z0-9]*)|\{([_a-z][_a-z0-9]*)\})`)

// expand expands a leading ~ and $VAR/${VAR} references from variables in
// value; unknown variables are left as they are, and $$ is $ (Python's
// string.Template.safe_substitute).
func expand(value string, variables map[string]string) string {
	if value == "~" || strings.HasPrefix(value, "~/") {
		value = "$HOME" + value[1:]
	}
	return templateRE.ReplaceAllStringFunc(value, func(m string) string {
		sub := templateRE.FindStringSubmatch(m)
		switch {
		case sub[1] != "":
			return "$"
		case sub[2] != "":
			if v, ok := variables[sub[2]]; ok {
				return v
			}
		case sub[3] != "":
			if v, ok := variables[sub[3]]; ok {
				return v
			}
		}
		return m
	})
}

// realpath resolves path's symlinks as far as they exist, keeping the rest
// as it is (Python's os.path.realpath).
func realpath(path string) string {
	if !filepath.IsAbs(path) {
		if wd, err := getwd(); err == nil {
			path = filepath.Join(wd, path)
		}
	}
	resolved, _ := joinRealpath("/", strings.TrimPrefix(path, "/"), map[string]*string{})
	return resolved
}

// joinRealpath resolves rest against the resolved path; seen maps links
// being resolved (nil while unresolved, for loops) to their results.
func joinRealpath(path, rest string, seen map[string]*string) (string, bool) {
	for rest != "" {
		name, tail, _ := strings.Cut(rest, "/")
		rest = tail
		switch name {
		case "", ".":
			continue
		case "..":
			path = filepath.Dir(path)
			continue
		}
		newpath := filepath.Join(path, name)
		fi, err := os.Lstat(newpath)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			path = newpath
			continue
		}
		if done, ok := seen[newpath]; ok {
			if done != nil {
				path = *done
				continue
			}
			// A loop: the rest as it is.
			return filepath.Join(newpath, rest), false
		}
		seen[newpath] = nil
		target, err := os.Readlink(newpath)
		if err != nil {
			path = newpath
			continue
		}
		base := path
		if filepath.IsAbs(target) {
			base = "/"
		}
		resolved, ok := joinRealpath(base, strings.TrimPrefix(target, "/"), seen)
		if !ok {
			return filepath.Join(resolved, rest), false
		}
		seen[newpath] = &resolved
		path = resolved
	}
	return path, true
}

func lexists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
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

// checkCwd refuses directories the read-write project bind must never
// cover.
func checkCwd(cwd, home string) error {
	// $PWD is bound read-write; in ~ (or above it) that would be the whole
	// host home over the volume.
	if strings.HasPrefix(home+"/", strings.TrimRight(cwd, "/")+"/") {
		return errorf("refusing to run in %s, it contains $HOME", cwd)
	}
	// The dot directories directly under ~ hold host state no sandbox
	// should write: ssh keys and config, every sandbox's volume, secrets and
	// exchange dir, the gh token, an ssh agent socket, ...
	if strings.HasPrefix(cwd+"/", home+"/.") {
		return errorf("refusing to run in %s, it is host state under $HOME", cwd)
	}
	return nil
}

// checkOutside refuses a cwd overlapping the state dir, which holds every
// sandbox's volume and secrets.
func checkOutside(cwd, stateDir string) error {
	if strings.HasPrefix(cwd+"/", strings.TrimRight(stateDir, "/")+"/") ||
		strings.HasPrefix(stateDir+"/", cwd+"/") {
		return errorf("refusing to run in %s, it overlaps the sandbox state dir %s", cwd, stateDir)
	}
	return nil
}

// projectRoot is the enclosing git work tree's top level (where .git is, as
// a directory or a worktree's file), or cwd itself outside one.
//
// Found by looking, not by running git: git on the host reads the repo's
// config, which the sandbox can write.
func projectRoot(cwd string) string {
	for candidate := cwd; ; candidate = filepath.Dir(candidate) {
		if exists(filepath.Join(candidate, ".git")) {
			return candidate
		}
		if candidate == "/" {
			return cwd
		}
	}
}

// volumeName is the per-project name: the path made flat, plus a hash so
// that flattening can't make two projects collide.
func volumeName(project string) string {
	digest := sha256.Sum256([]byte(project))
	return strings.ReplaceAll(project, "/", "_") + "-" + hex.EncodeToString(digest[:])[:8]
}

func isWithin(path, dir string) bool {
	return strings.HasPrefix(path+"/", strings.TrimRight(dir, "/")+"/")
}

var storePathRE = regexp.MustCompile(`^/nix/store/[0-9a-z]{32}-[^/]+(/[^/]+)*$`)

func isStorePath(value string) bool {
	if !storePathRE.MatchString(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// writeJSON writes value atomically, indented with sorted keys, into a
// directory only the host can write.
func writeJSON(path string, value any) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// pyQuote is s as a JSON string as Python's json.dumps writes it (ASCII
// only), for cache keys computed the same way by every version.
func pyQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e && r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r >= 0x10000:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
