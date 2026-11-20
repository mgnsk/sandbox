package secretservice

import (
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
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

type world struct {
	address, db string
	service     *dbus.Conn
	client      *dbus.Conn
}

func newWorld(t *testing.T) *world {
	w := &world{address: bus(t), db: filepath.Join(t.TempDir(), "secrets.sqlite3")}
	w.start(t)
	var err error
	if w.client, err = dbus.Connect(w.address); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.client.Close() })
	return w
}

// start serves the Secret Service on the bus, as a new sandbox's guard does.
func (w *world) start(t *testing.T) {
	t.Helper()
	st, err := OpenStore(w.db)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dbus.Connect(w.address)
	if err != nil {
		t.Fatal(err)
	}
	if err := Export(conn, st); err != nil {
		t.Fatal(err)
	}
	w.service = conn
	t.Cleanup(func() {
		conn.Close()
		st.Close()
	})
}

func (w *world) restart(t *testing.T) {
	w.service.Close()
	w.start(t)
}

func (w *world) call(path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	return w.client.Object(serviceName, path).Call(method, 0, args...)
}

func (w *world) create(t *testing.T, label string, attrs map[string]string, value []byte, replace bool) dbus.ObjectPath {
	t.Helper()
	props := map[string]dbus.Variant{
		itemIface + ".Label":      dbus.MakeVariant(label),
		itemIface + ".Attributes": dbus.MakeVariant(attrs),
	}
	var item, prompt dbus.ObjectPath
	err := w.call(collectionPath, collectionIface+".CreateItem", props,
		secret{"/org/freedesktop/secrets/session/s1", []byte{}, value, "text/plain"}, replace).Store(&item, &prompt)
	if err != nil {
		t.Fatal(err)
	}
	if prompt != "/" {
		t.Errorf("prompt %q", prompt)
	}
	return item
}

func (w *world) search(t *testing.T, attrs map[string]string) []dbus.ObjectPath {
	t.Helper()
	var items []dbus.ObjectPath
	if err := w.call(collectionPath, collectionIface+".SearchItems", attrs).Store(&items); err != nil {
		t.Fatal(err)
	}
	slices.Sort(items)
	return items
}

func (w *world) get(item dbus.ObjectPath) (secret, error) {
	var s secret
	err := w.call(item, itemIface+".GetSecret", dbus.ObjectPath("/s")).Store(&s)
	return s, err
}

func TestStoreSearchGet(t *testing.T) {
	w := newWorld(t)
	item := w.create(t, "label", map[string]string{"service": "gh", "account": "me"}, []byte("secret1"), true)
	for _, attrs := range []map[string]string{{"service": "gh"}, {"service": "gh", "account": "me"}, {}} {
		if got := w.search(t, attrs); !slices.Equal(got, []dbus.ObjectPath{item}) {
			t.Errorf("search %v: %v", attrs, got)
		}
	}
	if got := w.search(t, map[string]string{"service": "gh", "account": "other"}); len(got) != 0 {
		t.Errorf("search found %v", got)
	}
	s, err := w.get(item)
	if err != nil || string(s.Value) != "secret1" || s.ContentType != "text/plain" || s.Session != "/s" {
		t.Errorf("get: %+v %v", s, err)
	}
}

func TestReplace(t *testing.T) {
	w := newWorld(t)
	attrs := map[string]string{"service": "gh"}
	first := w.create(t, "label1", attrs, []byte("old"), true)
	if again := w.create(t, "label2", attrs, []byte("new"), true); again != first {
		t.Errorf("replaced as %s", again)
	}
	if s, _ := w.get(first); string(s.Value) != "new" {
		t.Errorf("value %q", s.Value)
	}
	// Exactly the same attributes: a superset is another item.
	if other := w.create(t, "label3", map[string]string{"service": "gh", "account": "me"}, []byte("x"), true); other == first {
		t.Error("superset replaced")
	}
	// Without replace, a duplicate is added.
	dup := w.create(t, "label4", attrs, []byte("dup"), false)
	if got := w.search(t, attrs); len(got) != 3 || !slices.Contains(got, dup) {
		t.Errorf("search %v", got)
	}
}

func TestBinarySecretsAndContentTypes(t *testing.T) {
	w := newWorld(t)
	value := make([]byte, 256)
	for i := range value {
		value[i] = byte(i)
	}
	var item, prompt dbus.ObjectPath
	props := map[string]dbus.Variant{
		itemIface + ".Label":      dbus.MakeVariant("bin"),
		itemIface + ".Attributes": dbus.MakeVariant(map[string]string{"k": "v"}),
	}
	if err := w.call(collectionPath, collectionIface+".CreateItem", props,
		secret{"/s", []byte{}, value, "application/octet-stream"}, true).Store(&item, &prompt); err != nil {
		t.Fatal(err)
	}
	if s, _ := w.get(item); !bytes.Equal(s.Value, value) || s.ContentType != "application/octet-stream" {
		t.Errorf("get %+v", s)
	}
}

func TestDelete(t *testing.T) {
	w := newWorld(t)
	item := w.create(t, "label", map[string]string{"service": "gh"}, []byte("x"), true)
	var prompt dbus.ObjectPath
	if err := w.call(item, itemIface+".Delete").Store(&prompt); err != nil || prompt != "/" {
		t.Fatalf("%v %q", err, prompt)
	}
	if got := w.search(t, map[string]string{"service": "gh"}); len(got) != 0 {
		t.Errorf("search %v", got)
	}
	if _, err := w.get(item); err == nil {
		t.Error("deleted item read")
	}
}

// A new sandbox starts a new guard on the same database.
func TestPersistence(t *testing.T) {
	w := newWorld(t)
	item := w.create(t, "label", map[string]string{"service": "gh"}, []byte("kept"), true)
	w.restart(t)
	// Exported again at start, before any search.
	if s, err := w.get(item); err != nil || string(s.Value) != "kept" {
		t.Errorf("get %+v %v", s, err)
	}
}

func TestService(t *testing.T) {
	w := newWorld(t)
	for _, want := range []dbus.ObjectPath{"/org/freedesktop/secrets/session/s1", "/org/freedesktop/secrets/session/s2"} {
		var output dbus.Variant
		var session dbus.ObjectPath
		if err := w.call(servicePath, serviceIface+".OpenSession", "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil || session != want {
			t.Errorf("session %q, %v", session, err)
		}
	}
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := w.call(servicePath, serviceIface+".Unlock", []dbus.ObjectPath{"/some/obj"}).Store(&unlocked, &prompt); err != nil ||
		!slices.Equal(unlocked, []dbus.ObjectPath{"/some/obj"}) || prompt != "/" {
		t.Errorf("unlock %v %q %v", unlocked, prompt, err)
	}
	// Empty, so go-keyring falls back to aliases/default directly.
	var collections dbus.Variant
	if err := w.call(servicePath, "org.freedesktop.DBus.Properties.Get", serviceIface, "Collections").Store(&collections); err != nil ||
		len(collections.Value().([]dbus.ObjectPath)) != 0 {
		t.Errorf("collections %v %v", collections, err)
	}
	// GDBus-based clients (libsecret) may look before they call.
	item := w.create(t, "label", map[string]string{"k": "v"}, []byte("x"), true)
	for path, method := range map[dbus.ObjectPath]string{servicePath: "OpenSession", collectionPath: "SearchItems", item: "GetSecret"} {
		var xml string
		if err := w.call(path, "org.freedesktop.DBus.Introspectable.Introspect").Store(&xml); err != nil || !strings.Contains(xml, `name="`+method+`"`) {
			t.Errorf("introspect %s: %v", path, err)
		}
	}
}

func TestWhatAClientGetsWrong(t *testing.T) {
	w := newWorld(t)
	for _, props := range []map[string]dbus.Variant{
		{itemIface + ".Attributes": dbus.MakeVariant(map[string]string{"k": "v"})},
		{itemIface + ".Label": dbus.MakeVariant("label")},
	} {
		if err := w.call(collectionPath, collectionIface+".CreateItem", props, secret{"/s", []byte{}, []byte("x"), "text/plain"}, true).Err; err == nil {
			t.Errorf("created with %v", props)
		}
	}
	if _, err := w.get("/org/freedesktop/secrets/item/42"); err == nil {
		t.Error("an item never stored read")
	}
}

// It holds credentials in plaintext; the default umask would make it 0644.
func TestDatabaseIsOwnerOnly(t *testing.T) {
	w := newWorld(t)
	w.create(t, "label", map[string]string{"service": "gh"}, []byte("topsecret"), true)
	for _, path := range []string{w.db, w.db + "-wal"} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", path, fi.Mode(), err)
		}
	}
	path := filepath.Join(t.TempDir(), "old.sqlite3")
	os.WriteFile(path, nil, 0o644)
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("a preexisting database left at %v", fi.Mode())
	}
}

// Attributes are stored as JSON, keys sorted, so equal sets read the same.
func TestAttributesAreStoredSorted(t *testing.T) {
	w := newWorld(t)
	attrs := map[string]string{"b": "1", "a": "2", "ü": "日本", "ctl": "\n\x01"}
	w.create(t, "label", attrs, []byte("x"), true)
	db, err := sql.Open("sqlite", w.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stored string
	if err := db.QueryRow("SELECT attributes FROM items").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if want := `{"a":"2","b":"1","ctl":"\n\u0001","ü":"日本"}`; stored != want {
		t.Errorf("stored %s, want %s", stored, want)
	}
	if got := w.search(t, attrs); len(got) != 1 {
		t.Errorf("search %v", got)
	}
}

// gh's logins are go-keyring items with service "gh:HOST", one per user.
func TestGhLogins(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "s.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if hosts, err := st.ghLogins(); err != nil || len(hosts) != 0 {
		t.Errorf("empty: %v %v", hosts, err)
	}
	for _, attrs := range []map[string]string{
		{"service": "gh:github.com", "username": ""},
		{"service": "gh:github.com", "username": "me"},
		{"service": "gh:ghe.example", "username": ""},
		{"service": "docker"},
	} {
		if _, err := st.put("x", attrs, "text/plain", []byte("t"), false); err != nil {
			t.Fatal(err)
		}
	}
	if hosts, err := st.ghLogins(); err != nil || !slices.Equal(hosts, []string{"ghe.example", "github.com"}) {
		t.Errorf("%v %v", hosts, err)
	}
}
