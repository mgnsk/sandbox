package tokens

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for token, want := range map[string]bool{
		"github_pat_" + strings.Repeat("t", 40): true,
		"gho_abc.~+/=-":                         true,
		strings.Repeat("x", 1024):               true,
		"short":                                 false,
		strings.Repeat("x", 1025):               false,
		"has space":                             false,
		"bad token\r\nX-Injected: 1":            false,
		"tab\there":                             false,
		"nonascii-ü-token":                      false,
	} {
		if got := Valid(token); got != want {
			t.Errorf("Valid(%q) = %v, want %v", token, got, want)
		}
	}
}

func TestReadWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "volume", ClaudeFile)
	if got := Read(path); got != "" {
		t.Fatalf("missing file: %q", got)
	}
	if err := Write(path, "bad token"); err == nil {
		t.Fatal("wrote an invalid token")
	}
	if err := Write(path, "github_pat_project0123"); err != nil {
		t.Fatal(err)
	}
	if got := Read(path); got != "github_pat_project0123" {
		t.Errorf("Read = %q", got)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
	// Malformed: as if there were none.
	if err := os.WriteFile(path, []byte("bad token\r\nX-Injected: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Read(path); got != "" {
		t.Errorf("malformed token read as %q", got)
	}
}

func TestWriteIsNotFooledByALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ClaudeFile)
	if err := os.Symlink(target, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, "github_pat_project0123"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(target); string(data) != "untouched" {
		t.Errorf("wrote through a link: %q", data)
	}
}
