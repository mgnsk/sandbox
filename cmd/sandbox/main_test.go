package main

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// The programs file, which nix and make link by, names each program.
func TestProgramsFile(t *testing.T) {
	data, err := os.ReadFile("programs")
	if err != nil {
		t.Fatal(err)
	}
	listed := strings.Fields(string(data))
	slices.Sort(listed)
	if have := slices.Sorted(maps.Keys(programs)); !slices.Equal(listed, have) {
		t.Errorf("programs file lists %v, the binary runs as %v", listed, have)
	}
}
