// Package waylandguard is the Wayland guard's two small parts in Go; the
// proxy itself is wl-veil (nix/packages.nix).
//
// wl-veil passes only an allowlist of Wayland globals on to its clients, so
// a window inside the sandbox can't reach what a compositor offers any
// client that asks: screen capture, the clipboard managers, synthetic
// input, other clients' windows. It serves for as long as a program it
// starts runs, and tells only that program where it listens. Run is that
// program: it reports the socket's name to the launcher and then just
// stays, until the launcher stops the guard.
package waylandguard

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"runtime"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/mgnsk/sandbox/internal/guard"
)

// Info is the guard's ready message.
type Info struct {
	// The socket's name in wl-veil's $XDG_RUNTIME_DIR, e.g. wayland-0.
	Display string `json:"display"`
}

// Run is the program wl-veil starts.
func Run(ctx context.Context) error {
	// wl-veil goes when it's killed, without stopping this: have the kernel
	// say so. The signal is tied to the thread that asks for it.
	runtime.LockOSThread()
	parent := os.Getppid()
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGTERM), 0, 0, 0); err != nil {
		return err
	}
	if os.Getppid() != parent {
		return errors.New("wl-veil is gone")
	}
	display := os.Getenv("WAYLAND_DISPLAY")
	if display == "" {
		return errors.New("no WAYLAND_DISPLAY from wl-veil")
	}
	if err := guard.Ready(Info{Display: display}); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// A global's interface name, e.g. wl_compositor: nothing wl-veil's -f
// would read as more than one name.
var globalName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// CheckGlobals checks the names of an allowlist's changes.
func CheckGlobals(globals map[string]bool) error {
	for _, name := range slices.Sorted(maps.Keys(globals)) {
		if !globalName.MatchString(name) {
			return fmt.Errorf("guards.wayland.globals: %q is not a Wayland global's name", name)
		}
	}
	return nil
}

// Globals is the allowlist: defaults, with each layer's changes on top in
// order - true adds a global, false removes it.
func Globals(defaults []string, layers ...map[string]bool) []string {
	allowed := map[string]bool{}
	for _, name := range defaults {
		allowed[name] = true
	}
	for _, layer := range layers {
		maps.Copy(allowed, layer)
	}
	var names []string
	for _, name := range slices.Sorted(maps.Keys(allowed)) {
		if allowed[name] {
			names = append(names, name)
		}
	}
	return names
}
