// Package testbin builds sandbox-bin for tests that run its subcommands as
// programs: the launcher, init and the guards.
package testbin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	once sync.Once
	dir  string
	err  error
)

// Path is sandbox-bin, built fresh from this module once per test process.
func Path(t testing.TB) string {
	t.Helper()
	once.Do(build)
	if err != nil {
		t.Fatalf("building sandbox-bin: %v", err)
	}
	return filepath.Join(dir, "sandbox-bin")
}

func build() {
	if dir, err = os.MkdirTemp("", "sandbox-bin-"); err != nil {
		return
	}
	root, err2 := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err = err2; err != nil {
		return
	}
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "sandbox-bin"), "./cmd/sandbox-bin")
	cmd.Dir = strings.TrimSpace(string(root))
	cmd.Stderr = os.Stderr
	err = cmd.Run()
}

// Main runs the tests, removing a binary built for them after: a test
// package's TestMain.
func Main(m *testing.M) {
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}
