package notify

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/mgnsk/sandbox/internal/popup"
)

const busConf = `<busconfig>
  <type>session</type>
  <listen>unix:path=%s</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`

// bus starts a private dbus-daemon for the test; its address.
func bus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("needs dbus-daemon")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "bus.conf")
	os.WriteFile(conf, fmt.Appendf(nil, busConf, filepath.Join(dir, "bus.sock")), 0o600)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--nopidfile", "--print-address=3")
	cmd.ExtraFiles = []*os.File{w}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	address, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(address)
}

// shown is one Notify call.
type shown struct {
	App, Summary, Body string
	Actions            []string
	Urgency            byte
	Timeout            int32
}

// daemon is a notification daemon on the test's bus.
type daemon struct {
	conn         *dbus.Conn
	capabilities []string
	mu           sync.Mutex
	shown        []shown
	closed       []uint32
}

func (d *daemon) GetCapabilities() ([]string, *dbus.Error) { return d.capabilities, nil }

func (d *daemon) Notify(app string, replaces uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	urgency, _ := hints["urgency"].Value().(byte)
	d.shown = append(d.shown, shown{app, summary, body, actions, urgency, timeout})
	return uint32(len(d.shown)), nil
}

func (d *daemon) CloseNotification(id uint32) *dbus.Error {
	d.mu.Lock()
	d.closed = append(d.closed, id)
	d.mu.Unlock()
	d.emit("NotificationClosed", id, uint32(closedByCall))
	return nil
}

func (d *daemon) emit(signal string, args ...any) {
	d.conn.Emit(path, service+"."+signal, args...)
}

func startDaemon(t *testing.T, address string, capabilities ...string) *daemon {
	t.Helper()
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	d := &daemon{conn: conn, capabilities: capabilities}
	if err := conn.Export(d, path, service); err != nil {
		t.Fatal(err)
	}
	if reply, err := conn.RequestName(service, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal(reply, err)
	}
	return d
}

func next(t *testing.T, n *Notifier) Event {
	t.Helper()
	select {
	case e := <-n.Events():
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
		return Event{}
	}
}

func TestConnect(t *testing.T) {
	if _, err := Connect("", "x"); err == nil {
		t.Error("connected without a bus")
	}
	address := bus(t)
	// No daemon on the bus.
	if _, err := Connect(address, "x"); err == nil {
		t.Error("connected without a daemon")
	}
	startDaemon(t, address, "body")
	if _, err := Connect(address, "x"); err == nil || !strings.Contains(err.Error(), "shows no actions") {
		t.Errorf("a daemon without actions: %v", err)
	}
}

func TestShowAndEvents(t *testing.T) {
	address := bus(t)
	d := startDaemon(t, address, "actions", "body", "body-markup")
	n, err := Connect(address, "sandbox tools")
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()

	id, err := n.Show(popup.Request{Name: "ssh-agent-guard", Text: "Allow SSH agent to sign?\n\n  command:  ssh <host> & more\x1b[0m\n"})
	if err != nil || id != 1 {
		t.Fatal(id, err)
	}
	got := d.shown[0]
	want := shown{App: "sandbox", Summary: "sandbox tools: ssh-agent-guard",
		// Markup made literal, escapes replaced.
		Body:    "Allow SSH agent to sign?\n\n  command:  ssh &lt;host&gt; &amp; more?[0m",
		Actions: []string{"once", "Allow once", "always", "Always in this sandbox", "no", "Deny"},
		// Critical, and never expiring: it stays until answered.
		Urgency: 2, Timeout: 0}
	if got.App != want.App || got.Summary != want.Summary || got.Body != want.Body ||
		!slices.Equal(got.Actions, want.Actions) || got.Urgency != want.Urgency || got.Timeout != want.Timeout {
		t.Errorf("shown %+v\n want %+v", got, want)
	}

	d.emit("ActionInvoked", uint32(1), "always")
	if e := next(t, n); e != (Event{ID: 1, Kind: Answered, Answer: popup.Always}) {
		t.Errorf("%+v", e)
	}
	// An action that isn't one of ours is a no.
	d.emit("ActionInvoked", uint32(1), "default")
	if e := next(t, n); e != (Event{ID: 1, Kind: Answered, Answer: popup.No}) {
		t.Errorf("%+v", e)
	}
	d.emit("NotificationClosed", uint32(1), uint32(2))
	if e := next(t, n); e != (Event{ID: 1, Kind: Dismissed}) {
		t.Errorf("%+v", e)
	}
	d.emit("NotificationClosed", uint32(1), uint32(1))
	if e := next(t, n); e != (Event{ID: 1, Kind: Gone}) {
		t.Errorf("%+v", e)
	}
	// Closed by us: the daemon is told, and that's no event.
	n.Close(1)
	d.emit("NotificationClosed", uint32(9), uint32(4))
	if e := next(t, n); e != (Event{ID: 9, Kind: Gone}) {
		t.Errorf("%+v", e)
	}
	if !slices.Equal(d.closed, []uint32{1}) {
		t.Errorf("closed %v", d.closed)
	}
}

// Text a daemon might cut is cut here instead, and says so.
func TestLongTextIsCutAndSaysSo(t *testing.T) {
	address := bus(t)
	d := startDaemon(t, address, "actions")
	n, err := Connect(address, "sandbox tools")
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()
	url := "https://example.com/?" + strings.Repeat("q=1&", 200)
	head := "Open in the host's browser?\n\n  host:     example.com\n\n"
	if _, err := n.Show(popup.Request{Name: "open-url-guard", Text: head + url + "\n"}); err != nil {
		t.Fatal(err)
	}
	got := d.shown[0]
	// Still answered here, on the start of it: the host comes first.
	if !slices.Equal(got.Actions, []string{"once", "Allow once", "always", "Always in this sandbox", "no", "Deny"}) {
		t.Errorf("actions %v", got.Actions)
	}
	if want := (head + url)[:maxBodyRunes] + "\n" + cutNote; got.Body != want {
		t.Errorf("body %q\n want %q", got.Body, want)
	}
	// Many lines: the first ones.
	body, whole := content(strings.Repeat("line\n", 50))
	if want := strings.TrimRight(strings.Repeat("line\n", maxBodyLines), "\n") + "\n" + cutNote; whole || body != want {
		t.Errorf("body %q, whole %v", body, whole)
	}

	for _, tc := range []struct {
		text  string
		whole bool
	}{
		{strings.Repeat("a", maxBodyRunes), true},
		{strings.Repeat("a", maxBodyRunes+1), false},
		{strings.Repeat("a\n", maxBodyLines), true},
		{strings.Repeat("a\n", maxBodyLines+1), false},
	} {
		if _, whole := content(tc.text); whole != tc.whole {
			t.Errorf("%d runes, %d lines: whole = %v", len(tc.text), strings.Count(tc.text, "\n"), whole)
		}
	}
	// Without body-markup, as it is.
	if _, err := n.Show(popup.Request{Name: "g", Text: "a <b> & c"}); err != nil || d.shown[1].Body != "a <b> & c" {
		t.Errorf("%q %v", d.shown[1].Body, err)
	}
}
