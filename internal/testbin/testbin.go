// Package testbin builds the sandbox binary for tests that run it as the
// programs it is: the launcher, sandbox-init and the guards.
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

// Dir is a directory with the binary and a link to it per program, built
// once per test process: $SANDBOX_BIN_DIR if set (a package's bin/), else
// fresh from this module.
func Dir(t testing.TB) string {
	t.Helper()
	once.Do(build)
	if err != nil {
		t.Fatalf("building the sandbox binary: %v", err)
	}
	return dir
}

func build() {
	if dir = os.Getenv("SANDBOX_BIN_DIR"); dir != "" {
		return
	}
	if dir, err = os.MkdirTemp("", "sandbox-bin-"); err != nil {
		return
	}
	root, err2 := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err = err2; err != nil {
		return
	}
	module := strings.TrimSpace(string(root))
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "sandbox"), "./cmd/sandbox")
	cmd.Dir = module
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return
	}
	programs, err2 := os.ReadFile(filepath.Join(module, "cmd/sandbox/programs"))
	if err = err2; err != nil {
		return
	}
	for _, p := range strings.Fields(string(programs)) {
		if p != "sandbox" {
			if err = os.Symlink("sandbox", filepath.Join(dir, p)); err != nil {
				return
			}
		}
	}
}

// Main runs the tests, removing a binary built for them after: a test
// package's TestMain.
func Main(m *testing.M) {
	code := m.Run()
	if dir != "" && os.Getenv("SANDBOX_BIN_DIR") == "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

// Program is the path of the program name.
func Program(t testing.TB, name string) string {
	return filepath.Join(Dir(t), name)
}
