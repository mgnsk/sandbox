// Package secretservicetest stands in for the host's side of
// secret-service-guard in tests: a session bus, and a keyring on it.
package secretservicetest

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
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

// Bus starts a private dbus-daemon for the test; its address. It skips the
// test without dbus-daemon.
func Bus(t testing.TB) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("needs dbus-daemon")
	}
	// Not t.TempDir(): it's named after the test, and a long test name
	// takes the socket's path past the 108 bytes a unix socket's may have.
	dir, err := os.MkdirTemp("", "bus-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, busConf, filepath.Join(dir, "bus.sock")), 0o600); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--nopidfile", "--print-address=3")
	cmd.ExtraFiles = []*os.File{w}
	cmd.Stderr = os.Stderr
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
		t.Fatalf("dbus-daemon didn't start: %v", err)
	}
	return strings.TrimSpace(address)
}

const (
	serviceName     = "org.freedesktop.secrets"
	servicePath     = "/org/freedesktop/secrets"
	CollectionPath  = "/org/freedesktop/secrets/collection/login"
	serviceIface    = "org.freedesktop.Secret.Service"
	collectionIface = "org.freedesktop.Secret.Collection"
	itemIface       = "org.freedesktop.Secret.Item"
	sessionIface    = "org.freedesktop.Secret.Session"
	promptIface     = "org.freedesktop.Secret.Prompt"
	nullPath        = dbus.ObjectPath("/")
)

// Item is a stored item.
type Item struct {
	Label       string
	Attributes  map[string]string
	Value       []byte
	ContentType string
}

type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// Keyring is a host Secret Service, with one collection: the default. The
// way gnome-keyring does, a locked one hides its items and unlocks after a
// prompt.
type Keyring struct {
	conn  *dbus.Conn
	props *prop.Properties // The collection's.

	mu       sync.Mutex
	locked   bool
	dismiss  bool
	items    map[dbus.ObjectPath]*Item
	sessions map[dbus.ObjectPath]bool
	next     int
	prompts  int
}

// Serve serves a keyring on a new connection to the bus at address, locked
// or not.
func Serve(t testing.TB, address string, locked bool) *Keyring {
	t.Helper()
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	k := &Keyring{conn: conn, locked: locked, items: map[dbus.ObjectPath]*Item{}, sessions: map[dbus.ObjectPath]bool{}}
	if err := conn.Export(service{k}, servicePath, serviceIface); err != nil {
		t.Fatal(err)
	}
	if err := conn.Export(collection{k}, CollectionPath, collectionIface); err != nil {
		t.Fatal(err)
	}
	k.props, err = prop.Export(conn, CollectionPath, prop.Map{collectionIface: {
		"Locked": {Value: locked, Emit: prop.EmitFalse},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if reply, err := conn.RequestName(serviceName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal(reply, err)
	}
	return k
}

// Lock locks the collection.
func (k *Keyring) Lock() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.locked = true
	k.props.SetMust(collectionIface, "Locked", true)
}

// DismissPrompts has every prompt from now on dismissed.
func (k *Keyring) DismissPrompts() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dismiss = true
}

// Prompts is how many prompts were shown.
func (k *Keyring) Prompts() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.prompts
}

// OpenSessions is how many sessions are open.
func (k *Keyring) OpenSessions() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.sessions)
}

// Items is a copy of the stored items.
func (k *Keyring) Items() []Item {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []Item
	for _, it := range k.items {
		c := *it
		c.Attributes = maps.Clone(it.Attributes)
		out = append(out, c)
	}
	return out
}

// Put stores an item as a host program would.
func (k *Keyring) Put(it Item) dbus.ObjectPath {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.putLocked(&it)
}

func (k *Keyring) putLocked(it *Item) dbus.ObjectPath {
	k.next++
	path := dbus.ObjectPath(CollectionPath + "/" + strconv.Itoa(k.next))
	k.items[path] = it
	_ = k.conn.Export(&item{k, path}, path, itemIface)
	_, _ = prop.Export(k.conn, path, prop.Map{itemIface: {
		"Attributes": {Value: maps.Clone(it.Attributes), Emit: prop.EmitFalse},
		"Label":      {Value: it.Label, Emit: prop.EmitFalse},
		"Created":    {Value: uint64(time.Now().Unix()), Emit: prop.EmitFalse},
		"Modified":   {Value: uint64(time.Now().Unix()), Emit: prop.EmitFalse},
	}})
	return path
}

var errLocked = &dbus.Error{Name: "org.freedesktop.Secret.Error.IsLocked", Body: []any{"locked"}}

// prompt makes a prompt that, once shown, runs done (unless dismissed) and
// completes with its result.
func (k *Keyring) prompt(done func() dbus.Variant) dbus.ObjectPath {
	k.prompts++
	path := dbus.ObjectPath(servicePath + "/prompt/p" + strconv.Itoa(k.prompts))
	_ = k.conn.Export(&prompt{k, path, done}, path, promptIface)
	return path
}

type prompt struct {
	k    *Keyring
	path dbus.ObjectPath
	done func() dbus.Variant
}

func (p *prompt) Prompt(windowID string) *dbus.Error {
	p.k.mu.Lock()
	dismiss := p.k.dismiss
	result := dbus.MakeVariant("")
	if !dismiss {
		result = p.done()
	}
	p.k.mu.Unlock()
	go p.k.conn.Emit(p.path, promptIface+".Completed", dismiss, result)
	return nil
}

func (p *prompt) Dismiss() *dbus.Error {
	go p.k.conn.Emit(p.path, promptIface+".Completed", true, dbus.MakeVariant(""))
	return nil
}

type service struct{ k *Keyring }

func (s service) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	if algorithm != "plain" {
		return dbus.Variant{}, "", &dbus.Error{Name: "org.freedesktop.DBus.Error.NotSupported", Body: []any{algorithm}}
	}
	s.k.mu.Lock()
	defer s.k.mu.Unlock()
	s.k.next++
	path := dbus.ObjectPath(servicePath + "/session/" + strconv.Itoa(s.k.next))
	s.k.sessions[path] = true
	_ = s.k.conn.Export(session{s.k, path}, path, sessionIface)
	return dbus.MakeVariant(""), path, nil
}

func (s service) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	if name == "default" {
		return CollectionPath, nil
	}
	return nullPath, nil
}

func (s service) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s.k.mu.Lock()
	defer s.k.mu.Unlock()
	if !s.k.locked {
		return objects, nullPath, nil
	}
	return []dbus.ObjectPath{}, s.k.prompt(func() dbus.Variant {
		s.k.locked = false
		s.k.props.SetMust(collectionIface, "Locked", false)
		return dbus.MakeVariant(objects)
	}), nil
}

type session struct {
	k    *Keyring
	path dbus.ObjectPath
}

func (s session) Close() *dbus.Error {
	s.k.mu.Lock()
	defer s.k.mu.Unlock()
	delete(s.k.sessions, s.path)
	s.k.conn.Export(nil, s.path, sessionIface)
	return nil
}

type collection struct{ k *Keyring }

func includes(have, want map[string]string) bool {
	for key, v := range want {
		if got, ok := have[key]; !ok || got != v {
			return false
		}
	}
	return true
}

func (c collection) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	c.k.mu.Lock()
	defer c.k.mu.Unlock()
	paths := []dbus.ObjectPath{}
	if c.k.locked {
		return paths, nil
	}
	for path, it := range c.k.items {
		if includes(it.Attributes, attrs) {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func (c collection) CreateItem(props map[string]dbus.Variant, s secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	c.k.mu.Lock()
	defer c.k.mu.Unlock()
	if c.k.locked {
		return "", "", errLocked
	}
	if !c.k.sessions[s.Session] {
		return "", "", &dbus.Error{Name: "org.freedesktop.Secret.Error.NoSession", Body: []any{string(s.Session)}}
	}
	label, _ := props[itemIface+".Label"].Value().(string)
	attrs, _ := props[itemIface+".Attributes"].Value().(map[string]string)
	it := &Item{Label: label, Attributes: attrs, Value: s.Value, ContentType: s.ContentType}
	if replace {
		for path, old := range c.k.items {
			if maps.Equal(old.Attributes, attrs) {
				c.k.items[path] = it
				return path, nullPath, nil
			}
		}
	}
	return c.k.putLocked(it), nullPath, nil
}

type item struct {
	k    *Keyring
	path dbus.ObjectPath
}

func (it *item) GetSecret(session dbus.ObjectPath) (secret, *dbus.Error) {
	it.k.mu.Lock()
	defer it.k.mu.Unlock()
	if it.k.locked {
		return secret{}, errLocked
	}
	if !it.k.sessions[session] {
		return secret{}, &dbus.Error{Name: "org.freedesktop.Secret.Error.NoSession", Body: []any{string(session)}}
	}
	stored, ok := it.k.items[it.path]
	if !ok {
		return secret{}, &dbus.Error{Name: "org.freedesktop.Secret.Error.NoSuchObject", Body: []any{"gone"}}
	}
	return secret{session, []byte{}, stored.Value, stored.ContentType}, nil
}

func (it *item) Delete() (dbus.ObjectPath, *dbus.Error) {
	it.k.mu.Lock()
	defer it.k.mu.Unlock()
	if it.k.locked {
		return "", errLocked
	}
	delete(it.k.items, it.path)
	return nullPath, nil
}
