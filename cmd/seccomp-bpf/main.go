// Writes the sandbox's seccomp filter, as `bwrap --seccomp` reads it, to
// stdout. Run at build time; see internal/seccomp.
package main

import (
	"fmt"
	"os"

	"github.com/mgnsk/sandbox/internal/seccomp"
)

func main() {
	prog, err := seccomp.Program()
	if err == nil {
		_, err = os.Stdout.Write(prog)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "seccomp-bpf:", err)
		os.Exit(1)
	}
}
