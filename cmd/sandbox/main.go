// The sandbox launcher, sandbox-init and the guards, as one binary: which
// program runs is picked by the name it was started under (argv[0]), so the
// package links each name to it.
package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mgnsk/sandbox/internal/initcmd"
)

var programs = map[string]func(args []string) int{
	"sandbox-init": initcmd.Main,
}

func main() {
	name := filepath.Base(os.Args[0])
	run, ok := programs[name]
	if !ok {
		names := slices.Sorted(maps.Keys(programs))
		fmt.Fprintf(os.Stderr, "%s: not a program of this binary, which runs as one of: %s\n",
			name, strings.Join(names, ", "))
		os.Exit(2)
	}
	os.Exit(run(os.Args))
}
