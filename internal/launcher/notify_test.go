package launcher

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/mgnsk/sandbox/internal/testbin"
)

// detached, inside, runs its arguments in a session of their own, without a
// controlling terminal: as a GUI program's children are.
func detached() int {
	syscall.Setsid()
	path, err := exec.LookPath(os.Args[1])
	if err != nil {
		return 127
	}
	if err := syscall.Exec(path, os.Args[1:], os.Environ()); err != nil {
		return 126
	}
	return 0
}

const notifications = "org.freedesktop.Notifications"

// notificationDaemon is a notification daemon on a bus of the test's own:
// it answers each notification with answer, a while after it's shown.
type notificationDaemon struct {
	conn   *dbus.Conn
	answer string
	mu     sync.Mutex
	shown  []string // Each notification's summary and body.
	closed []uint32
}

func (d *notificationDaemon) GetCapabilities() ([]string, *dbus.Error) {
	return []string{"actions", "body"}, nil
}

func (d *notificationDaemon) Notify(app string, replaces uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.shown = append(d.shown, summary+"\n"+body)
	id := uint32(len(d.shown))
	if d.answer != "" {
		// Past the popups' grace period.
		time.AfterFunc(700*time.Millisecond, func() {
			d.conn.Emit("/org/freedesktop/Notifications", notifications+".ActionInvoked", id, d.answer)
		})
	}
	return id, nil
}

func (d *notificationDaemon) CloseNotification(id uint32) *dbus.Error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = append(d.closed, id)
	return nil
}

func (d *notificationDaemon) seen() ([]string, []uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string{}, d.shown...), append([]uint32{}, d.closed...)
}

// notificationBus starts a session bus with a notification daemon on it;
// the bus's address.
func (h *harness) notificationBus(answer string) (string, *notificationDaemon) {
	h.t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		h.t.Skip("needs dbus-daemon")
	}
	conf := filepath.Join(h.tmp, "session.conf")
	os.WriteFile(conf, fmt.Appendf(nil, busConf, filepath.Join(h.tmp, "session.sock")), 0o600)
	r, w, err := os.Pipe()
	if err != nil {
		h.t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--nopidfile", "--print-address=3")
	cmd.ExtraFiles = []*os.File{w}
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	w.Close()
	h.t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		h.t.Fatal(err)
	}
	address := strings.TrimSpace(line)
	conn, err := dbus.Connect(address)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { conn.Close() })
	d := &notificationDaemon{conn: conn, answer: answer}
	if err := conn.Export(d, "/org/freedesktop/Notifications", notifications); err != nil {
		h.t.Fatal(err)
	}
	if reply, err := conn.RequestName(notifications, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		h.t.Fatal(reply, err)
	}
	return address, d
}

// In a sandbox with a display, a request from a program that isn't on the
// sandbox's terminal is a desktop notification too, and answered there.
func TestPopupsAsNotifications(t *testing.T) {
	h := newHarness(t)
	address, d := h.notificationBus("once")
	h.waylandOn("wl_compositor")
	h.cfg.Guards.Notifications = true
	h.cfg.Guards.OpenURL = true
	log := filepath.Join(h.tmp, "xdg.log")
	os.WriteFile(filepath.Join(h.hostBin, "xdg-open"), []byte("#!/bin/sh\necho \"$*\" >> "+log+"\n"), 0o755)
	env := map[string]string{"WAYLAND_DISPLAY": h.compositor(), "DBUS_SESSION_BUS_ADDRESS": address}

	p := h.pty(env, h.tool("detached"), testbin.Path(t), "xdg-open", "https://example.org/x")
	p.expect("D = never:") // On the terminal all the same.
	if r := p.wait(); r.code != 0 {
		t.Fatalf("%d %q", r.code, r.stdout)
	}
	shown, _ := d.seen()
	if len(shown) != 1 || !strings.HasPrefix(shown[0], "sandbox p: open-url-guard\nOpen in the host's browser?") ||
		!strings.Contains(shown[0], "https://example.org/x") {
		t.Errorf("shown %q", shown)
	}
	var opened []byte
	for deadline := time.Now().Add(10 * time.Second); len(opened) == 0 && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		opened, _ = os.ReadFile(log)
	}
	if string(opened) != "https://example.org/x\n" {
		t.Errorf("opened %q", opened)
	}

	// From the terminal itself: asked there alone.
	d.answer = ""
	p = h.pty(env, testbin.Path(t), "xdg-open", "https://example.org/y")
	p.expect("D = never:")
	time.Sleep(600 * time.Millisecond)
	p.send("n\r")
	if r := p.wait(); r.code != 4 {
		t.Errorf("%d %q", r.code, r.stdout)
	}
	if shown, _ := d.seen(); len(shown) != 1 {
		t.Errorf("shown %q", shown)
	}

	// Answered on the terminal: the notification is taken away.
	p = h.pty(env, h.tool("detached"), testbin.Path(t), "xdg-open", "https://example.org/z")
	p.expect("D = never:")
	time.Sleep(600 * time.Millisecond)
	p.send("n\r")
	if r := p.wait(); r.code != 4 {
		t.Errorf("%d %q", r.code, r.stdout)
	}
	if shown, closed := d.seen(); len(shown) != 2 || len(closed) != 1 || closed[0] != 2 {
		t.Errorf("shown %q, closed %v", shown, closed)
	}

	// Turned off, or without a display inside: the terminal alone.
	h.cfg.Guards.Notifications = false
	p = h.pty(env, h.tool("detached"), testbin.Path(t), "xdg-open", "https://example.org/a")
	p.expect("D = never:")
	time.Sleep(600 * time.Millisecond)
	p.send("n\r")
	p.wait()
	h.cfg.Guards.Notifications = true
	h.cfg.Guards.Wayland.Enable = nil
	p = h.pty(env, h.tool("detached"), testbin.Path(t), "xdg-open", "https://example.org/b")
	p.expect("D = never:")
	time.Sleep(600 * time.Millisecond)
	p.send("n\r")
	p.wait()
	if shown, _ := d.seen(); len(shown) != 2 {
		t.Errorf("shown %q", shown)
	}

	// No daemon to ask: said once, and the terminal still asks.
	h.waylandOn("wl_compositor")
	env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + filepath.Join(h.tmp, "nowhere.sock")
	p = h.pty(env, h.tool("detached"), testbin.Path(t), "xdg-open", "https://example.org/c")
	if shown := p.expect("D = never:"); !strings.Contains(shown, "no desktop notifications") {
		t.Errorf("%q", shown)
	}
	time.Sleep(600 * time.Millisecond)
	p.send("n\r")
	if r := p.wait(); r.code != 4 {
		t.Errorf("%d %q", r.code, r.stdout)
	}
}
