package initcmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mgnsk/sandbox/internal/testbin"
)

func TestMain(m *testing.M) { testbin.Main(m) }

type env struct {
	home, store, current string
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	e := &env{home: filepath.Join(dir, "home"), store: filepath.Join(dir, "store")}
	os.Mkdir(e.home, 0o755)
	os.Mkdir(e.store, 0o755)
	return e
}

// generation makes a home-files tree of links to store files current; the
// tree.
func (e *env) generation(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	gen := filepath.Join(e.store, name+"-home-manager-files")
	os.Mkdir(gen, 0o755)
	for rel, content := range files {
		src := filepath.Join(e.store, name+"-"+strings.ReplaceAll(rel, "/", "-"))
		os.WriteFile(src, []byte(content), 0o644)
		os.MkdirAll(filepath.Dir(filepath.Join(gen, rel)), 0o755)
		if err := os.Symlink(src, filepath.Join(gen, rel)); err != nil {
			t.Fatal(err)
		}
	}
	e.current = filepath.Join(e.store, name+"-home-manager-generation")
	os.Mkdir(e.current, 0o755)
	os.Symlink(gen, filepath.Join(e.current, "home-files"))
	return gen
}

func (e *env) link(t *testing.T) {
	t.Helper()
	if err := linkGeneration(e.home, e.current); err != nil {
		t.Fatal(err)
	}
}

func (e *env) read(rel string) string {
	data, _ := os.ReadFile(filepath.Join(e.home, rel))
	return string(data)
}

func isLink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func TestLinksEveryFileIntoTheGeneration(t *testing.T) {
	e := newEnv(t)
	gen := e.generation(t, "a", map[string]string{".bashrc": "a\n", ".config/foo/conf": "foo\n"})
	e.link(t)
	if target, _ := os.Readlink(filepath.Join(e.home, ".bashrc")); target != filepath.Join(gen, ".bashrc") {
		t.Errorf(".bashrc -> %s", target)
	}
	if got := e.read(".config/foo/conf"); got != "foo\n" {
		t.Errorf("conf %q", got)
	}
	// For tools that diff a build against the current generation.
	if target, _ := os.Readlink(filepath.Join(e.home, ".local/state/nix/profiles/home-manager")); target != e.current {
		t.Errorf("profile -> %s", target)
	}
}

func TestASwitchRelinks(t *testing.T) {
	e := newEnv(t)
	old := e.generation(t, "a", map[string]string{".bashrc": "a\n", ".config/old": "old\n", ".config/foo": "a\n"})
	e.link(t)
	// An old generation may be gone by the next start.
	os.RemoveAll(old)
	e.generation(t, "b", map[string]string{".bashrc": "b\n", ".config/new": "new\n", ".config/foo/bar": "b\n"})
	e.link(t)
	if got := e.read(".bashrc"); got != "b\n" {
		t.Errorf(".bashrc %q", got)
	}
	if isLink(filepath.Join(e.home, ".config/old")) {
		t.Error("removed file still linked")
	}
	// A file split into a directory.
	if got := e.read(".config/foo/bar"); got != "b\n" {
		t.Errorf("foo/bar %q", got)
	}
}

// Links of another generation are looked for all over the volume, which is
// slow in a large one: only after a switch, not at every start.
func TestTheVolumeIsSearchedOnlyAfterASwitch(t *testing.T) {
	e := newEnv(t)
	old := e.generation(t, "a", map[string]string{".bashrc": "a\n"})
	e.link(t)
	if linked, _ := os.ReadFile(filepath.Join(e.home, generationMarker)); string(linked) != e.current {
		t.Fatalf("marker %q, generation %q", linked, e.current)
	}
	// Not init's doing, so only a search would find it.
	stray := filepath.Join(e.home, "deep/in/a/cache/link")
	os.MkdirAll(filepath.Dir(stray), 0o755)
	os.Symlink(filepath.Join(old, ".bashrc"), stray)
	e.link(t)
	if !isLink(stray) {
		t.Error("the volume was searched without a switch")
	}
	e.generation(t, "b", map[string]string{".bashrc": "b\n"})
	e.link(t)
	if isLink(stray) {
		t.Error("a link into the old generation outlived the switch")
	}
}

func TestLeavesTheVolumesOwnFilesAlone(t *testing.T) {
	e := newEnv(t)
	e.generation(t, "a", map[string]string{".config/managed": "a\n"})
	e.link(t)
	managed := filepath.Join(e.home, ".config/managed")
	os.Remove(managed)
	os.WriteFile(managed, []byte("the sandbox's own\n"), 0o644)
	os.Symlink("/nonexistent", filepath.Join(e.home, "broken"))
	os.Symlink("/nix/store/abc-foo/bar", filepath.Join(e.home, "other"))
	// Into the same store, but not to a generation's files.
	os.Symlink(filepath.Join(e.store, "abc-tool/bin/tool"), filepath.Join(e.home, "tool"))
	e.generation(t, "b", nil)
	e.link(t)
	if got := e.read(".config/managed"); got != "the sandbox's own\n" {
		t.Errorf("managed %q", got)
	}
	for _, name := range []string{"broken", "other", "tool"} {
		if !isLink(filepath.Join(e.home, name)) {
			t.Errorf("%s removed", name)
		}
	}
}

func TestWhatIsInTheWay(t *testing.T) {
	e := newEnv(t)
	os.Mkdir(filepath.Join(e.home, ".stub"), 0o755)
	os.WriteFile(filepath.Join(e.home, ".copy"), []byte("stale\n"), 0o644)
	os.MkdirAll(filepath.Join(e.home, ".full"), 0o755)
	os.WriteFile(filepath.Join(e.home, ".full/keep"), []byte("keep\n"), 0o644)
	e.generation(t, "a", map[string]string{".stub": "s\n", ".copy": "c\n", ".full": "f\n"})
	e.link(t)
	if e.read(".stub") != "s\n" || e.read(".copy") != "c\n" || e.read(".full/keep") != "keep\n" {
		t.Errorf("%q %q %q", e.read(".stub"), e.read(".copy"), e.read(".full/keep"))
	}
}

func TestRelinkReplacesALeftoverTempLink(t *testing.T) {
	dir := t.TempDir()
	os.Symlink("/nonexistent", filepath.Join(dir, "..bashrc.sandbox-init"))
	if err := relink(filepath.Join(dir, ".bashrc"), "/target"); err != nil {
		t.Fatal(err)
	}
	if target, _ := os.Readlink(filepath.Join(dir, ".bashrc")); target != "/target" {
		t.Errorf("-> %s", target)
	}
	if isLink(filepath.Join(dir, "..bashrc.sandbox-init")) {
		t.Error("temp link left")
	}
}

func TestKnownMarketplaces(t *testing.T) {
	home, managed := t.TempDir(), t.TempDir()
	link := filepath.Join(home, ".claude/plugins/known_marketplaces.json")
	target := filepath.Join(managed, "known_marketplaces.json")
	// A fresh volume has no list; with no managed one, nothing is made.
	linkKnownMarketplaces(home, managed)
	if _, err := os.Lstat(filepath.Dir(link)); err == nil {
		t.Error("made a dir for nothing")
	}
	// One Claude Code wrote itself is replaced.
	os.MkdirAll(filepath.Dir(link), 0o755)
	os.WriteFile(link, []byte("{}"), 0o644)
	os.WriteFile(target, []byte(`{"sandbox": {}}`), 0o644)
	linkKnownMarketplaces(home, managed)
	if got, _ := os.Readlink(link); got != target {
		t.Errorf("-> %q", got)
	}
	// Gone from the configuration, the link goes too.
	os.Remove(target)
	linkKnownMarketplaces(home, managed)
	if isLink(link) {
		t.Error("link kept")
	}
	// The volume's own list, without a managed one, stays.
	os.WriteFile(link, []byte("{}"), 0o644)
	linkKnownMarketplaces(home, managed)
	if data, _ := os.ReadFile(link); string(data) != "{}" {
		t.Errorf("own list %q", data)
	}
}

func TestGhConfig(t *testing.T) {
	home := t.TempDir()
	writeGhConfig(home)
	path := filepath.Join(home, ".config/gh/config.yml")
	if data, _ := os.ReadFile(path); string(data) != "git_protocol: ssh\n" {
		t.Errorf("config %q", data)
	}
	// An existing one is the sandbox's own, a link too.
	os.Remove(path)
	os.Symlink("/nonexistent", path)
	writeGhConfig(home)
	if !isLink(path) {
		t.Error("replaced")
	}
}

func TestMountPointsAreUnescaped(t *testing.T) {
	if got := mountinfoUnescape.Replace(`/home/u/a\040b\134c`); got != `/home/u/a b\c` {
		t.Errorf("%q", got)
	}
}

// -- as a program --

func run(t *testing.T, home string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(testbin.Path(t), append([]string{"init"}, args...)...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.String(), errOut.String(), err
}

func TestLinksTheProfileAndExecsTheCommand(t *testing.T) {
	e := newEnv(t)
	e.generation(t, "a", map[string]string{".bashrc": "a\n"})
	out, errOut, err := run(t, e.home, "/nix/profile", e.current, "echo", "ran")
	if err != nil || out != "ran\n" {
		t.Fatalf("%v %q %q", err, out, errOut)
	}
	if target, _ := os.Readlink(filepath.Join(e.home, ".nix-profile")); target != "/nix/profile" {
		t.Errorf(".nix-profile -> %s", target)
	}
	if e.read(".bashrc") != "a\n" {
		t.Error("generation not linked")
	}
}

func TestWithoutProfileOrGenerationOnlyExecs(t *testing.T) {
	home := t.TempDir()
	if out, _, err := run(t, home, "", "", "echo", "ran"); err != nil || out != "ran\n" {
		t.Fatalf("%v %q", err, out)
	}
	if isLink(filepath.Join(home, ".nix-profile")) {
		t.Error("profile linked")
	}
	// A generation that's gone is skipped.
	if out, _, err := run(t, home, "", filepath.Join(home, "gone"), "echo", "ran"); err != nil || out != "ran\n" {
		t.Fatalf("%v %q", err, out)
	}
}

func TestACommandThatCannotRunFails(t *testing.T) {
	home := t.TempDir()
	_, errOut, err := run(t, home, "", "", "nonexistent-command")
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 127 || !strings.Contains(errOut, "command not found") {
		t.Errorf("%v %q", err, errOut)
	}
	if _, _, err := run(t, home, "", ""); err == nil {
		t.Error("ran without a command")
	}
}

// -- in a mount namespace --

func bwrap(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bwrap")
	if err != nil || exec.Command(path, "--unshare-user", "--dev-bind", "/", "/", "true").Run() != nil {
		t.Skip("needs bwrap and unprivileged user namespaces (unavailable inside a sandbox)")
	}
	return path
}

// A bind under $HOME (a repo, say) may hold links that look like
// generation links; they're not the volume's to remove.
func TestSkipsMountsOverTheVolume(t *testing.T) {
	bw := bwrap(t)
	e := newEnv(t)
	old := e.generation(t, "a", map[string]string{".bashrc": "a\n"})
	repo := filepath.Join(t.TempDir(), "repo with space")
	os.Mkdir(repo, 0o755)
	os.Symlink(filepath.Join(old, ".bashrc"), filepath.Join(repo, "link"))
	mounted := filepath.Join(e.home, "mounted dir")
	os.Mkdir(mounted, 0o755)
	e.generation(t, "b", map[string]string{".bashrc": "b\n"})
	cmd := exec.Command(bw, "--unshare-user", "--dev-bind", "/", "/", "--bind", repo, mounted, "--",
		testbin.Path(t), "init", "", e.current, "true")
	cmd.Env = []string{"HOME=" + e.home, "PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if !isLink(filepath.Join(repo, "link")) {
		t.Error("a link in a mount was removed")
	}
	if e.read(".bashrc") != "b\n" {
		t.Error("not relinked")
	}
}

func TestWithoutThemRemovesWhatAnEarlierStartLinked(t *testing.T) {
	e := newEnv(t)
	e.generation(t, "a", map[string]string{".bashrc": "a\n", ".config/foo/conf": "foo\n"})
	if _, errOut, err := run(t, e.home, "/nix/profile", e.current, "true"); err != nil {
		t.Fatalf("%v %q", err, errOut)
	}
	os.WriteFile(filepath.Join(e.home, ".config/own"), []byte("own\n"), 0o644)
	out, errOut, err := run(t, e.home, "", "", "echo", "ran")
	if err != nil || out != "ran\n" {
		t.Fatalf("%v %q %q", err, out, errOut)
	}
	for _, rel := range []string{".nix-profile", ".bashrc", ".config/foo/conf", ".local/state/nix/profiles/home-manager"} {
		if isLink(filepath.Join(e.home, rel)) {
			t.Errorf("%s still linked", rel)
		}
	}
	if e.read(".config/own") != "own\n" {
		t.Error("the volume's own file is gone")
	}
	// The next start without it links them again.
	if _, errOut, err := run(t, e.home, "/nix/profile", e.current, "true"); err != nil || e.read(".bashrc") != "a\n" {
		t.Fatalf("%v %q", err, errOut)
	}
}

func TestWithoutThemLeavesAProfileOfTheVolume(t *testing.T) {
	home := t.TempDir()
	own := filepath.Join(home, ".local/state/nix/profiles/profile")
	os.MkdirAll(own, 0o755)
	os.Symlink(own, filepath.Join(home, ".nix-profile"))
	// Nothing linked before: nothing to remove either.
	if out, errOut, err := run(t, home, "", "", "echo", "ran"); err != nil || out != "ran\n" {
		t.Fatalf("%v %q %q", err, out, errOut)
	}
	if !isLink(filepath.Join(home, ".nix-profile")) {
		t.Error("the volume's own profile is unlinked")
	}
}
