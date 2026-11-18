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
	"github.com/mgnsk/sandbox/internal/openurl"
	"github.com/mgnsk/sandbox/internal/secretservice"
	"github.com/mgnsk/sandbox/internal/sshagent"
	"github.com/mgnsk/sandbox/internal/xdgopen"
)

// Each also listed in the programs file, which the package links by.
var programs = map[string]func(args []string) int{
	"sandbox-init":         initcmd.Main,
	"open-url-guard":       openurl.Main,
	"sandbox-xdg-open":     xdgopen.Main,
	"ssh-agent-guard":      sshagent.Main,
	"secret-service-guard": secretservice.Main,
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
