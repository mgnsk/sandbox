package launcher

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	projectFileName = "sandbox.nix"
	userConfigFile  = "config.nix"
	// Set for the launcher that evaluates sandbox.nix, so it doesn't repeat
	// the upgrade notice.
	quietEnv = "SANDBOX_NO_UPGRADE_NOTICE"

	githubTokenFile   = "github-token"
	forgejoTokensFile = "forgejo-tokens.json"
)

type options struct {
	reload        bool
	projectConfig bool
	claudeAPIKey  bool
	ghToken       bool
	fjToken       string
}

// parseOptions takes the launcher's own leading options; the command
// after them.
func parseOptions(args []string) (options, []string, error) {
	opts := options{projectConfig: true}
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		arg := args[0]
		args = args[1:]
		switch arg {
		case "--":
			return opts, args, nil
		case "--reload":
			opts.reload = true
		case "--no-project-config":
			opts.projectConfig = false
		case "--claude-api-key":
			opts.claudeAPIKey = true
		case "--gh-token":
			opts.ghToken = true
		case "--fj-token":
			if len(args) == 0 || strings.HasPrefix(args[0], "--") {
				return opts, nil, errorf("--fj-token needs the Forgejo host, e.g. --fj-token codeberg.org")
			}
			host, err := forgejoHost(args[0])
			if err != nil {
				return opts, nil, err
			}
			opts.fjToken, args = host, args[1:]
		default:
			return opts, nil, errorf("unknown option %s (put -- before a command starting with --)", arg)
		}
	}
	return opts, args, nil
}

var (
	forgejoHostRE = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?$`)
	schemeRE      = regexp.MustCompile(`^https?://`)
)

// forgejoHost is host[:port] from a host or an instance URL.
func forgejoHost(value string) (string, error) {
	host := schemeRE.ReplaceAllString(strings.ToLower(pyStrip(value)), "")
	host, _, _ = strings.Cut(host, "/")
	host = strings.TrimSuffix(host, ":443")
	if !forgejoHostRE.MatchString(host) {
		return "", errorf("not a Forgejo host: %s", value)
	}
	return host, nil
}

// pyStrip strips whitespace as Python's str.strip does.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r == ' ' || r >= '\t' && r <= '\r' || r >= 0x1c && r <= 0x1f || r == 0x85 ||
			r == 0xa0 || r == 0x1680 || r >= 0x2000 && r <= 0x200a || r == 0x2028 ||
			r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000
	})
}

// -- your config (~/.config/sandbox/config.nix) --------------------------------

// userConfigFiles lists every file under the config dir (through symlinks
// to files, which dotfiles managers make), sorted: what the cache key
// covers.
func userConfigFiles(dir string) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if isFile(path) {
			files = append(files, path)
		}
		if e.IsDir() {
			dirs = append(dirs, path)
		}
	}
	for _, d := range dirs {
		files = append(files, userConfigFiles(d)...)
	}
	return files
}

// storePathOut is the last store path among the lines of out.
func storePathOut(out string) string {
	last := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if isStorePath(line) {
			last = line
		}
	}
	return last
}

// runCapturing runs argv with no stdin, its stdout captured and its stderr
// the launcher's; interrupted says whether a Ctrl-C came meanwhile.
func (l *launcher) runCapturing(argv []string, env []string) (out string, ok, interrupted bool) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stderr = os.Stderr
	l.interrupted.Store(false)
	l.inSubprocess.Store(true)
	stdout, err := cmd.Output()
	l.inSubprocess.Store(false)
	return string(stdout), err == nil, l.interrupted.Load()
}

func (l *launcher) buildUserConfig(ref *userConfigRef, file, link string) (string, error) {
	nixBuild, err := exec.LookPath("nix-build")
	if err != nil {
		return "", errorf("building %s needs nix-build on PATH", file)
	}
	argv := []string{
		nixBuild, ref.Eval,
		"--argstr", "nixpkgs", ref.Nixpkgs,
		"--argstr", "system", ref.System,
		"--argstr", "file", file,
		"--out-link", link,
	}
	fmt.Fprintf(os.Stderr, "sandbox: building %s\n", file)
	out, ok, interrupted := l.runCapturing(argv, os.Environ())
	if interrupted {
		return "", errorf("building %s interrupted", file)
	}
	path := storePathOut(out)
	if !ok || path == "" {
		return "", errorf("building %s failed", file)
	}
	return path, nil
}

type cacheEntry struct {
	Key    string `json:"key"`
	Config string `json:"config,omitempty"`
	// For project.json.
	Manifest string `json:"manifest,omitempty"`
}

// userConfig is the config to run with: the one built from
// ~/.config/sandbox/config.nix when this sandbox takes one and it exists,
// else this one. Cached until a file in ~/.config/sandbox or this sandbox
// changes; imports from outside that dir aren't tracked, --reload picks
// them up.
func (l *launcher) userConfig(cfg *config, configPath, home, project string, reload bool) (string, *config, error) {
	if cfg.UserConfig == nil {
		return configPath, cfg, nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = home + "/.config"
	}
	configDir := filepath.Join(base, "sandbox")
	file := filepath.Join(configDir, userConfigFile)
	if !isFile(file) {
		return configPath, cfg, nil
	}
	files := userConfigFiles(configDir)
	// It's built and run on the host: not from anywhere a sandbox can write.
	for _, path := range append([]string{configDir}, files...) {
		if real := realpath(path); isWithin(real, project) {
			return "", nil, errorf("refusing to use %s: %s is in this project, which the sandbox can write", file, real)
		}
	}
	digest := sha256.New()
	digest.Write([]byte(realpath(configPath)))
	for _, path := range files {
		rel, _ := filepath.Rel(configDir, path)
		digest.Write([]byte(pyQuote(rel)))
		data, err := os.ReadFile(path)
		if err != nil {
			return "", nil, errorf("can't read %s: %v", path, err)
		}
		sum := sha256.Sum256(data)
		digest.Write(sum[:])
	}
	key := hex.EncodeToString(digest.Sum(nil))

	stateBase := os.Getenv("XDG_STATE_HOME")
	if stateBase == "" {
		stateBase = home + "/.local/state"
	}
	state := filepath.Join(stateBase, "sandbox")
	if err := os.MkdirAll(state, 0o777); err != nil {
		return "", nil, err
	}
	cache := filepath.Join(state, "config.json")
	out := ""
	if !reload {
		var cached cacheEntry
		if data, err := os.ReadFile(cache); err == nil && json.Unmarshal(data, &cached) == nil &&
			cached.Key == key && isStorePath(cached.Config) && isFile(cached.Config) {
			out = cached.Config
		}
	}
	if out == "" {
		var err error
		out, err = l.buildUserConfig(cfg.UserConfig, file, filepath.Join(state, "config"))
		if err != nil {
			return "", nil, err
		}
		if err := writeJSON(cache, map[string]string{"key": key, "config": out}); err != nil {
			return "", nil, err
		}
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return "", nil, errorf("can't read the %s result %s: %v", file, out, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", nil, errorf("can't read the %s result %s: %v", file, out, err)
	}
	if uc, ok := raw["userConfig"]; ok && string(uc) != "null" {
		return "", nil, errorf("bad %s result %s", file, out)
	}
	built := &config{}
	if err := json.Unmarshal(data, built); err != nil {
		return "", nil, errorf("bad %s result %s: %v", file, out, err)
	}
	return out, built, nil
}

// -- project config (sandbox.nix) ----------------------------------------------

type manifest struct {
	ClaudeDir *string
	Binds     []bind
	HostPorts []string
	Command   []string
}

func strList(v any) ([]string, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func parseBind(v any) (bind, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 5 {
		return bind{}, false
	}
	var b bind
	src, ok1 := m["src"].(string)
	mode, ok2 := m["mode"].(string)
	optional, ok3 := m["optional"].(bool)
	hideGit, ok4 := m["hideGit"].(bool)
	dst, hasDst := m["dst"]
	if !ok1 || !ok2 || !ok3 || !ok4 || !hasDst || (mode != "ro" && mode != "rw") {
		return bind{}, false
	}
	b.Src, b.Mode, b.Optional, b.HideGit = src, mode, optional, hideGit
	switch d := dst.(type) {
	case nil:
	case string:
		b.Dst = &d
	default:
		return bind{}, false
	}
	return b, true
}

// readManifest reads what project.nix made of sandbox.nix. It comes out of
// a sandbox, so every field is checked before the launcher uses it.
func readManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	var raw any
	if err == nil {
		err = json.Unmarshal(data, &raw)
	}
	if err != nil {
		return nil, errorf("can't read the %s result %s: %v", projectFileName, path, err)
	}
	obj, ok := raw.(map[string]any)
	fields := []string{"claudeDir", "binds", "hostPorts", "command"}
	if ok && len(obj) == len(fields) {
		for _, f := range fields {
			if _, has := obj[f]; !has {
				ok = false
			}
		}
	} else {
		ok = false
	}
	if !ok {
		return nil, errorf("bad %s result %s", projectFileName, path)
	}
	bad := func(name string) error { return errorf("bad %s result %s: %s", projectFileName, path, name) }
	m := &manifest{}
	switch v := obj["claudeDir"].(type) {
	case nil:
	case string:
		if !isStorePath(v) {
			return nil, bad("claudeDir")
		}
		m.ClaudeDir = &v
	default:
		return nil, bad("claudeDir")
	}
	binds, ok := obj["binds"].([]any)
	if !ok {
		return nil, bad("binds")
	}
	m.Binds = []bind{}
	for _, item := range binds {
		b, ok := parseBind(item)
		if !ok {
			return nil, bad("binds")
		}
		m.Binds = append(m.Binds, b)
	}
	if m.HostPorts, ok = strList(obj["hostPorts"]); !ok {
		return nil, bad("hostPorts")
	}
	if obj["command"] != nil {
		if m.Command, ok = strList(obj["command"]); !ok || len(m.Command) == 0 {
			return nil, bad("command")
		}
	}
	return m, nil
}

// readProjectFile reads sandbox.nix's bytes, for the cache key. Not through
// a symlink, which would have the launcher read a host file of the
// sandbox's choosing.
func readProjectFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errorf("can't read %s: %s (it must be a regular file)", path, strerror(err))
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, errorf("%s must be a regular file", path)
	}
	return io.ReadAll(f)
}

// evaluateProject builds sandbox.nix's manifest with nix inside a sandbox
// of the project (without its sandbox.nix); its store path.
func (l *launcher) evaluateProject(cfg *config, configPath, projectFile, base string) (string, error) {
	argv := []string{
		l.self, configPath, "--no-project-config", "--",
		"nix", "build", "--no-link", "--print-out-paths", "--file", cfg.Project.Eval,
		"--argstr", "nixpkgs", cfg.Project.Nixpkgs,
		"--argstr", "system", cfg.Project.System,
		"--argstr", "file", projectFile,
		"--argstr", "base", base,
	}
	fmt.Fprintf(os.Stderr, "sandbox: evaluating %s\n", projectFile)
	out, ok, interrupted := l.runCapturing(argv, append(os.Environ(), quietEnv+"=1"))
	if interrupted {
		return "", errorf("evaluating %s interrupted", projectFile)
	}
	if !ok {
		return "", errorf("evaluating %s failed", projectFile)
	}
	// The login shell's startup files may print too; the build's output is
	// the last line.
	path := storePathOut(out)
	if path == "" {
		return "", errorf("evaluating %s gave no result", projectFile)
	}
	return path, nil
}

// projectManifest is sandbox.nix's manifest, from the cache while
// sandbox.nix, the sandbox's own config and the profile's Claude config are
// unchanged. Files sandbox.nix imports aren't tracked; --reload picks them
// up.
func (l *launcher) projectManifest(cfg *config, configPath, project, volumeDir, base string, reload bool) (*manifest, error) {
	projectFile := filepath.Join(project, projectFileName)
	content, err := readProjectFile(projectFile)
	if err != nil {
		return nil, err
	}
	keyText := "[" + pyQuote(realpath(configPath)) + ", " + pyQuote(base) + ", " +
		pyQuote(hex.EncodeToString(content)) + "]"
	sum := sha256.Sum256([]byte(keyText))
	key := hex.EncodeToString(sum[:])
	cache := filepath.Join(volumeDir, "project.json")
	if !reload {
		var cached cacheEntry
		if data, err := os.ReadFile(cache); err == nil && json.Unmarshal(data, &cached) == nil &&
			cached.Key == key && isStorePath(cached.Manifest) && isFile(cached.Manifest) {
			return readManifest(cached.Manifest)
		}
	}
	out, err := l.evaluateProject(cfg, configPath, projectFile, base)
	if err != nil {
		return nil, err
	}
	m, err := readManifest(out)
	if err != nil {
		return nil, err
	}
	if err := writeJSON(cache, map[string]string{"key": key, "manifest": out}); err != nil {
		return nil, err
	}
	return m, nil
}

// hostAccess is what sandbox.nix asks for beyond the inside of the sandbox,
// as approved and stored.
type hostAccess struct {
	Binds     []bind   `json:"binds"`
	HostPorts []string `json:"hostPorts"`
}

func describeHostAccess(access hostAccess) string {
	var lines []string
	for _, b := range access.Binds {
		dst := ""
		if b.Dst != nil && *b.Dst != "" {
			dst = " at " + *b.Dst
		}
		extra := ""
		if b.Optional {
			extra = ", optional"
		}
		mode := "read-only"
		if b.Mode == "rw" {
			mode = "read-write"
		}
		lines = append(lines, fmt.Sprintf("  bind %s%s (%s%s)", b.Src, dst, mode, extra))
	}
	for _, p := range access.HostPorts {
		lines = append(lines, "  host port "+p)
	}
	return strings.Join(lines, "\n")
}

// tty is the controlling terminal, also when stdin/stdout are redirected.
type tty struct {
	f *os.File
	r *bufio.Reader
}

var openTTY = func() (*tty, error) {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "/dev/tty")
	return &tty{f: f, r: bufio.NewReaderSize(f, 1)}, nil
}

func (t *tty) write(s string) { _, _ = t.f.WriteString(s) }

func (t *tty) readLine() string {
	line, _ := t.r.ReadString('\n')
	return pyStrip(line)
}

func (t *tty) close() { t.f.Close() }

// readSecret reads a line from the terminal without echoing it.
func (t *tty) readSecret(prompt string) string {
	t.write(prompt)
	fd := int(t.f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return t.readLine()
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	_ = unix.IoctlSetTermios(fd, unix.TCSETSF, &quiet)
	defer func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETSF, old)
		t.write("\n")
	}()
	return t.readLine()
}

// sameJSON says whether a and b are equal as JSON values.
func sameJSON(a []byte, b any) bool {
	var x, y any
	data, err := json.Marshal(b)
	if err != nil || json.Unmarshal(a, &x) != nil || json.Unmarshal(data, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// approveProject asks for a yes on the terminal to binds and host ports
// from sandbox.nix, again whenever they change: the sandbox can edit
// sandbox.nix, so its say-so alone must never widen the next sandbox. The
// approval is stored in the volume dir, out of the sandbox's reach.
func approveProject(m *manifest, volumeDir, projectFile string) error {
	access := hostAccess{Binds: m.Binds, HostPorts: m.HostPorts}
	if len(access.Binds) == 0 && len(access.HostPorts) == 0 {
		return nil
	}
	approvedFile := filepath.Join(volumeDir, "project-approved.json")
	if data, err := os.ReadFile(approvedFile); err == nil && sameJSON(data, access) {
		return nil
	}
	text := fmt.Sprintf("sandbox: %s asks for host access:\n%s\n", projectFile, describeHostAccess(access))
	t, err := openTTY()
	if err != nil {
		return errorf("%s asks for host access that isn't approved yet; start the sandbox from a terminal to approve it", projectFile)
	}
	t.write(text + "Allow? [y/N] ")
	answer := strings.ToLower(t.readLine())
	t.close()
	if answer != "y" && answer != "yes" {
		return errorf("host access not approved, not starting")
	}
	return writeJSON(approvedFile, access)
}

// applyProject is the profile with sandbox.nix's additions: its binds on
// top, and its Claude config (already merged with the profile's by
// project.nix) in place of the profile's.
func applyProject(p profile, m *manifest) profile {
	p.Binds = append(slices.Clone(p.Binds), m.Binds...)
	switch {
	case p.ClaudeDir == nil || *p.ClaudeDir == "":
		p.ClaudeDir = nil
	case m.ClaudeDir != nil && *m.ClaudeDir != "":
		p.ClaudeDir = m.ClaudeDir
	}
	return p
}

// -- secrets ------------------------------------------------------------------------

var (
	claudeAPIKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{20,512}$`)
	tokenChars     = regexp.MustCompile(`^[A-Za-z0-9_.~+/=-]+$`)
)

// validToken is as apiproxy's: 8 to 1024 characters, no whitespace or
// control characters.
func validToken(token string) bool {
	return len(token) >= 8 && len(token) <= 1024 && tokenChars.MatchString(token)
}

// writeSecret replaces the file at path (in a volume dir, never in the
// home volume the sandbox writes) with text, readable only by the user.
func writeSecret(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if lexists(tmp) {
		if err := os.Remove(tmp); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// claudeAPIKey is the file for the project's Claude API key, asking for the
// key on the terminal when there's none yet (or askAgain). It's in the
// volume dir, out of the sandbox's reach; claude-api-proxy reads it per
// request, so a key set later reaches a running sandbox.
func claudeAPIKey(volumeDir string, askAgain bool) (string, error) {
	keyFile := filepath.Join(volumeDir, "claude-api-key")
	if exists(keyFile) && !askAgain {
		return keyFile, nil
	}
	t, err := openTTY()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: no Claude API key for this project yet - run `sandbox --claude-api-key` from a terminal")
		return keyFile, nil
	}
	defer t.close()
	t.write("sandbox: Claude Code here uses an API key that stays outside the sandbox.\n" +
		"Create one for this project at https://platform.claude.com/settings/keys\n" +
		"(a workspace with a spend limit caps what a misbehaving sandbox can spend).\n")
	key := t.readSecret("API key (Enter to skip): ")
	if key != "" && !claudeAPIKeyRE.MatchString(key) {
		t.write("sandbox: that doesn't look like an API key, not saved\n")
		key = ""
	}
	if key == "" {
		if !exists(keyFile) {
			t.write("sandbox: no key - Claude Code inside can't reach the API until `sandbox --claude-api-key` sets one\n")
		}
		return keyFile, nil
	}
	return keyFile, writeSecret(keyFile, key+"\n")
}

// askToken reads a token on the terminal (hidden input); "" when skipped
// or malformed.
func askToken(intro, prompt string) (string, error) {
	if os.Getenv("SANDBOX_EXCHANGE") != "" {
		// Only a hint, not a control: in here it would land in this
		// sandbox's volume, where no proxy reads it.
		return "", errorf("this is inside a sandbox - set the token on the host, in the project")
	}
	t, err := openTTY()
	if err != nil {
		return "", errorf("setting a token needs a terminal - run it in one on the host, in the project")
	}
	defer t.close()
	t.write(intro)
	token := t.readSecret(prompt)
	if token != "" && !validToken(token) {
		t.write("sandbox: that doesn't look like a token, not saved\n")
		return "", nil
	}
	if token == "" {
		t.write("sandbox: nothing changed\n")
	}
	return token, nil
}

// setGitHubToken asks for the project's GitHub token and keeps it in the
// volume dir, out of the sandbox's reach; gh-api-proxy prefers it to the
// host gh's.
func setGitHubToken(volumeDir string) error {
	token, err := askToken(
		"sandbox: gh in this project uses a token that stays outside the sandbox.\n"+
			"Create a fine-grained token limited to this project's repositories at\n"+
			"https://github.com/settings/personal-access-tokens/new\n"+
			"(a token, not a `gh auth login`: GitHub caps how many OAuth logins stay valid).\n",
		"GitHub token (Enter to keep the current one): ")
	if err != nil || token == "" {
		return err
	}
	return writeSecret(filepath.Join(volumeDir, githubTokenFile), token+"\n")
}

// setForgejoToken asks for the project's token for the Forgejo instance at
// host and adds it to the volume dir's {host: token} file;
// forgejo-api-proxy prefers it to the host fj's.
func setForgejoToken(volumeDir, host string) error {
	token, err := askToken(
		fmt.Sprintf("sandbox: fj in this project uses a token for %s that stays outside the sandbox.\n"+
			"Create one at https://%s/user/settings/applications\n", host, host),
		fmt.Sprintf("Token for %s (Enter to keep the current one): ", host))
	if err != nil || token == "" {
		return err
	}
	path := filepath.Join(volumeDir, forgejoTokensFile)
	tokens := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		var existing any
		if json.Unmarshal(data, &existing) == nil {
			if m, ok := existing.(map[string]any); ok {
				tokens = m
			}
		}
	}
	tokens[host] = token
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(tokens); err != nil {
		return err
	}
	return writeSecret(path, b.String())
}

// strerror words err's errno as the C library does ("No such file or
// directory").
func strerror(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s := errno.Error()
		return strings.ToUpper(s[:1]) + s[1:]
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
