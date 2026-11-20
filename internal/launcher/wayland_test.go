package launcher

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// fakeWlVeil stands in for wl-veil: it listens at wayland-0 in its
// $XDG_RUNTIME_DIR, answers each connection with its allowlist and the
// display it proxies, and runs the program after "--" with WAYLAND_DISPLAY
// naming its socket, until that exits.
func fakeWlVeil() int {
	// The program is told when the thread that started it ends.
	runtime.LockOSThread()
	args := os.Args[1:]
	dir, upstream := os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("WAYLAND_DISPLAY")
	writeLog(logEntry{Tool: "wl-veil", Argv: args, Files: map[string]string{
		"XDG_RUNTIME_DIR": dir, "WAYLAND_DISPLAY": upstream, "RUST_LOG": os.Getenv("RUST_LOG")}})
	at := slices.Index(args, "--")
	if at < 0 || len(args) < 4 || args[0] != "-i" || args[1] != "-f" {
		return 2
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "wayland-0"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(c, "%s via %s\n", args[2], upstream)
			c.Close()
		}
	}()
	cmd := exec.Command(args[at+1], args[at+2:]...)
	cmd.Env = append(os.Environ(), "WAYLAND_DISPLAY=wayland-0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// The launcher's ready pipe, as wl-veil's child inherits it.
	cmd.ExtraFiles = []*os.File{os.NewFile(3, "ready")}
	if err := cmd.Run(); err != nil {
		return 1
	}
	return 0
}

// waylandCheck, inside, prints what the display at $WAYLAND_DISPLAY says.
func waylandCheck() int {
	c, err := net.Dial("unix", filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("WAYLAND_DISPLAY")))
	if err != nil {
		fmt.Println(err)
		return 1
	}
	io.Copy(os.Stdout, c)
	return 0
}

// compositor is a socket standing in for the host's Wayland display; its
// name for $WAYLAND_DISPLAY.
func (h *harness) compositor() string {
	h.t.Helper()
	ln, err := net.Listen("unix", filepath.Join(h.runtime, "wayland-9"))
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { ln.Close() })
	return "wayland-9"
}

func (h *harness) waylandOn(defaults ...string) {
	on := true
	h.cfg.Guards.Wayland.Enable = &on
	h.cfg.Guards.Wayland.DefaultGlobals = defaults
	h.cfg.Tools.WlVeil = h.tool("wl-veil")
}

func TestWaylandGuard(t *testing.T) {
	h := newHarness(t)
	// Off unless asked for, and nothing of the host's display inside.
	display := h.compositor()
	r := h.run("", map[string]string{"WAYLAND_DISPLAY": display})
	if inv := r.pasta(t); r.code != 0 || inv.setenv()["WAYLAND_DISPLAY"] != "" || len(r.calls("wl-veil")) != 0 {
		t.Errorf("%d %q", r.code, r.stderr)
	}

	h.waylandOn("xdg_wm_base", "wl_compositor", "wl_shm")
	// No display on the host: none inside.
	r = h.run("", map[string]string{"WAYLAND_DISPLAY": ""})
	if !strings.Contains(r.stderr, "no Wayland display ($WAYLAND_DISPLAY unset), none inside") || r.pasta(t).setenv()["WAYLAND_DISPLAY"] != "" {
		t.Errorf("%q", r.stderr)
	}
	r = h.run("", map[string]string{"WAYLAND_DISPLAY": "wayland-7"})
	if !strings.Contains(r.stderr, "no Wayland display at "+h.runtime+"/wayland-7, none inside") || r.pasta(t).setenv()["WAYLAND_DISPLAY"] != "" {
		t.Errorf("%q", r.stderr)
	}

	// The proxy's socket inside, with the allowlist: the defaults and the
	// user's changes.
	h.cfg.Guards.Wayland.Globals = map[string]bool{"wl_shm": false, "wl_data_device_manager": true}
	r = h.run("", map[string]string{"WAYLAND_DISPLAY": display, "WAYLAND_SOCKET": "7"}, h.tool("wayland-check"))
	inv := r.pasta(t)
	upstream := h.runtime + "/" + display
	if want := "wl_compositor,wl_data_device_manager,xdg_wm_base via " + upstream + "\n"; r.code != 0 || r.stdout != want {
		t.Errorf("%d %q %q, want %q", r.code, r.stdout, r.stderr, want)
	}
	if inv.setenv()["WAYLAND_DISPLAY"] != "wayland-0" {
		t.Errorf("WAYLAND_DISPLAY %q", inv.setenv()["WAYLAND_DISPLAY"])
	}
	// Never the real socket, and the proxy's is somewhere of its own.
	if slices.ContainsFunc(inv.mounts(), func(m string) bool { return strings.Contains(m, display) }) {
		t.Errorf("the host's display is bound in: %q", inv.mounts())
	}
	var veil logEntry
	for _, e := range r.log {
		if e.Tool == "wl-veil" {
			veil = e
		}
	}
	if dir := veil.Files["XDG_RUNTIME_DIR"]; dir == "" || dir == h.runtime || inv.bind(t, h.runtime+"/wayland-0") != dir+"/wayland-0" {
		t.Errorf("wl-veil in %q, bound %q", dir, inv.mounts())
	}
	if veil.Files["RUST_LOG"] != "error" || filepath.Base(veil.Argv[len(veil.Argv)-1]) != "wayland-guard" {
		t.Errorf("%+v", veil)
	}
	// Gone with the sandbox.
	if entries, _ := os.ReadDir(h.tmpdir); len(entries) != 0 {
		t.Errorf("left %v", entries)
	}

	// An absolute $WAYLAND_DISPLAY.
	r = h.run("", map[string]string{"WAYLAND_DISPLAY": upstream}, h.tool("wayland-check"))
	if !strings.HasSuffix(r.stdout, " via "+upstream+"\n") {
		t.Errorf("%q %q", r.stdout, r.stderr)
	}

	// Config errors stop the start.
	h.cfg.Guards.Wayland.Globals = map[string]bool{"wl_compositor": false, "wl_shm": false, "xdg_wm_base": false}
	h.run("", map[string]string{"WAYLAND_DISPLAY": display}).refused(t, "guards.wayland.globals allows no global")
	h.cfg.Guards.Wayland.Globals = map[string]bool{"wl_shm,zwlr_screencopy_manager_v1": true}
	h.run("", map[string]string{"WAYLAND_DISPLAY": display}).refused(t, "is not a Wayland global's name")
	h.cfg.Guards.Wayland.Globals = nil
	h.cfg.Tools.WlVeil, _ = exec.LookPath("false")
	h.run("", map[string]string{"WAYLAND_DISPLAY": display}).refused(t, "wl-veil exited with status 1")
}

// A project's sandbox.nix can ask for the display and change the
// allowlist: widening takes a yes, and the user's own config has the last
// word on both.
func TestWaylandFromTheProject(t *testing.T) {
	h := newHarness(t)
	h.cfg.Guards.Wayland.DefaultGlobals = []string{"wl_compositor", "wl_shm", "xdg_wm_base"}
	h.cfg.Tools.WlVeil = h.tool("wl-veil")
	env := map[string]string{"WAYLAND_DISPLAY": h.compositor()}
	m := manifest{Command: []string{h.tool("wayland-check")},
		Wayland: waylandAccess{Enable: true, Globals: map[string]bool{"wl_data_device_manager": true, "wl_shm": false}}}
	h.withProject(m, "{ ... }: { }\n", "m.json")
	if r := h.run("", env); r.code != 1 || !strings.Contains(r.stderr, "start the sandbox from a terminal to approve it") {
		t.Errorf("%d %q", r.code, r.stderr)
	}
	p := h.pty(env)
	shown := p.expect("Allow? [y/N] ")
	for _, want := range []string{"windows on this host's Wayland display",
		"Wayland clients inside with the global wl_data_device_manager",
		"Wayland clients inside without the global wl_shm"} {
		if !strings.Contains(shown, want) {
			t.Errorf("%q not in %q", want, shown)
		}
	}
	p.send("y\r")
	if r := p.wait(); r.code != 0 || !strings.Contains(r.stdout, "wl_compositor,wl_data_device_manager,xdg_wm_base via ") {
		t.Errorf("%d %q", r.code, r.stdout)
	}

	// The user's changes go over the project's.
	h.cfg.Guards.Wayland.Globals = map[string]bool{"wl_data_device_manager": false, "wl_shm": true}
	if r := h.run("", env); r.code != 0 || !strings.HasPrefix(r.stdout, "wl_compositor,wl_shm,xdg_wm_base via ") {
		t.Errorf("%d %q %q", r.code, r.stdout, r.stderr)
	}

	// Off in the user's config: off, and nothing to approve.
	off := false
	h.cfg.Guards.Wayland.Enable = &off
	m.Wayland.Globals["zwlr_screencopy_manager_v1"] = true
	m.Command = []string{"true"}
	h.withProject(m, "{ ... }: { x = 1; }\n", "m2.json")
	r := h.run("", env)
	if inv := r.pasta(t); r.code != 0 || inv.setenv()["WAYLAND_DISPLAY"] != "" || len(r.calls("wl-veil")) != 0 {
		t.Errorf("%d %q", r.code, r.stderr)
	}

	// On in the user's config, a project that only takes globals away has
	// nothing to approve either.
	h.waylandOn("wl_compositor", "wl_shm", "xdg_wm_base")
	h.cfg.Guards.Wayland.Globals = nil
	narrow := manifest{Command: []string{h.tool("wayland-check")},
		Wayland: waylandAccess{Globals: map[string]bool{"wl_shm": false}}}
	h.withProject(narrow, "{ ... }: { x = 2; }\n", "m3.json")
	if r := h.run("", env); r.code != 0 || !strings.HasPrefix(r.stdout, "wl_compositor,xdg_wm_base via ") {
		t.Errorf("%d %q %q", r.code, r.stdout, r.stderr)
	}
}

func TestWaylandAccess(t *testing.T) {
	for _, tc := range []struct {
		w    waylandAccess
		want bool
	}{
		{waylandAccess{}, false},
		{waylandAccess{Globals: map[string]bool{"wl_shm": false}}, false},
		{waylandAccess{Enable: true}, true},
		{waylandAccess{Globals: map[string]bool{"wl_shm": false, "wl_drm": true}}, true},
	} {
		if got := tc.w.widens(); got != tc.want {
			t.Errorf("%+v widens = %v", tc.w, got)
		}
	}
	access := hostAccess{Wayland: &waylandAccess{Enable: true, Globals: map[string]bool{"b_x": true, "a_y": false}}}
	want := "  windows on this host's Wayland display\n" +
		"  Wayland clients inside without the global a_y\n" +
		"  Wayland clients inside with the global b_x"
	if got := access.String(); got != want {
		t.Errorf("%q", got)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	os.WriteFile(path, []byte(`{"wayland": {"enable": true, "globals": {"wl_shm": false}}}`), 0o644)
	if m, err := readManifest(path); err != nil || !m.Wayland.Enable || m.Wayland.Globals["wl_shm"] {
		t.Errorf("%+v %v", m, err)
	}
	for _, bad := range []string{
		`{"wayland": {"enable": true, "globals": {"a,b": true}}}`,
		`{"wayland": {"enable": "yes"}}`,
		`{"wayland": {"enable": true, "socket": "/run/user/1000/wayland-1"}}`,
	} {
		os.WriteFile(path, []byte(bad), 0o644)
		if _, err := readManifest(path); err == nil {
			t.Errorf("%s read", bad)
		}
	}
}
