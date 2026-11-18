// Package cover writes coverage counters of a binary built with -cover
// before the process ends in a way that skips Go's own exit hooks: an exec,
// or a signal. A no-op otherwise.
package cover

import (
	"os"
	"runtime/coverage"
)

// Flush writes the counters to $GOCOVERDIR, if set.
func Flush() {
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		return
	}
	// Errors only mean the binary wasn't built with -cover (and
	// -covermode=atomic, which writing counters early needs).
	_ = coverage.WriteMetaDir(dir)
	_ = coverage.WriteCountersDir(dir)
}
