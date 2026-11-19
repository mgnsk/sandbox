// Package cover writes coverage counters of a binary built with -cover
// before the process ends in a way that skips Go's own exit hooks: an exec,
// or a signal. A no-op otherwise.
package cover

import (
	"os"
	"os/signal"
	"runtime/coverage"
	"syscall"
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

// DieOnSignals makes SIGTERM and SIGINT end the process as their default
// action would - killed by the signal - after writing the counters.
func DieOnSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := (<-ch).(syscall.Signal)
		Flush()
		signal.Reset(sig)
		_ = syscall.Kill(os.Getpid(), sig)
	}()
}

// ExitOnTerm makes SIGTERM a clean exit (status 0), after writing the
// counters.
func ExitOnTerm() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		Flush()
		os.Exit(0)
	}()
}
