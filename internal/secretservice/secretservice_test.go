package secretservice

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/mgnsk/sandbox/internal/secretservice/secretservicetest"
)

const project = "/home/u/proj"

type world struct {
	address string
	host    string // The host's session bus.
	keyring *secretservicetest.Keyring
	service *dbus.Conn
	client  *dbus.Conn
	session dbus.ObjectPath // A plain one.
}

func newWorld(t *testing.T) *world {
	return newWorldLocked(t, false)
}

func newWorldLocked(t *testing.T, locked bool) *world {
	w := &world{address: secretservicetest.Bus(t), host: secretservicetest.Bus(t)}
	w.keyring = secretservicetest.Serve(t, w.host, locked)
	w.start(t)
	var err error
	if w.client, err = dbus.Connect(w.address); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.client.Close() })
	w.session = w.openSession(t)
	return w
}

func (w *world) openSession(t *testing.T) dbus.ObjectPath {
	t.Helper()
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := w.call(servicePath, serviceIface+".OpenSession", "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		t.Fatal(err)
	}
	return session
}

// start serves the Secret Service on the bus, as a new sandbox's guard does.
func (w *world) start(t *testing.T) {
	t.Helper()
	host, err := ConnectHost(t.Context(), w.host, project)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dbus.Connect(w.address)
	if err != nil {
		t.Fatal(err)
	}
	if err := Export(conn, host); err != nil {
		t.Fatal(err)
	}
	w.service = conn
	t.Cleanup(func() {
		conn.Close()
		host.Close()
	})
}

func (w *world) restart(t *testing.T) {
	w.service.Close()
	w.start(t)
	w.session = w.openSession(t)
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
		secret{w.session, []byte{}, value, "text/plain"}, replace).Store(&item, &prompt)
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
	err := w.call(item, itemIface+".GetSecret", w.session).Store(&s)
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
	if err != nil || string(s.Value) != "secret1" || s.ContentType != "text/plain" || s.Session != w.session {
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
		secret{w.session, []byte{}, value, "application/octet-stream"}, true).Store(&item, &prompt); err != nil {
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
	found := w.search(t, map[string]string{"service": "gh"})
	if len(found) != 1 || found[0] != item {
		t.Fatalf("search %v", found)
	}
	if s, err := w.get(found[0]); err != nil || string(s.Value) != "kept" {
		t.Errorf("get %+v %v", s, err)
	}
}

func TestService(t *testing.T) {
	w := newWorld(t)
	for _, want := range []dbus.ObjectPath{"/org/freedesktop/secrets/session/s2", "/org/freedesktop/secrets/session/s3"} {
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
		if err := w.call(collectionPath, collectionIface+".CreateItem", props, secret{w.session, []byte{}, []byte("x"), "text/plain"}, true).Err; err == nil {
			t.Errorf("created with %v", props)
		}
	}
	if _, err := w.get("/org/freedesktop/secrets/item/42"); err == nil {
		t.Error("an item never stored read")
	}
}

// On the host, an item is the project's, its attributes prefixed, and its
// label says where it's from.
func TestStoredOnTheHost(t *testing.T) {
	w := newWorld(t)
	attrs := map[string]string{"service": "gh:github.com", "username": "me"}
	w.create(t, "gh token", attrs, []byte("tok"), true)
	items := w.keyring.Items()
	if len(items) != 1 {
		t.Fatalf("%+v", items)
	}
	want := map[string]string{ProjectAttribute: project, "sandbox:service": "gh:github.com", "sandbox:username": "me"}
	if it := items[0]; !maps.Equal(it.Attributes, want) || it.Label != "sandbox proj: gh token" || string(it.Value) != "tok" {
		t.Errorf("%+v", it)
	}
	// Every session opened for a transfer is closed again.
	if n := w.keyring.OpenSessions(); n != 0 {
		t.Errorf("%d sessions open", n)
	}
}

// A sandbox sees only its own project's items: not another project's, not
// the host's own, even with the same attributes.
func TestProjectsAreSeparate(t *testing.T) {
	w := newWorld(t)
	w.keyring.Put(secretservicetest.Item{Label: "host gh", Attributes: map[string]string{"service": "gh:github.com"}, Value: []byte("host")})
	w.keyring.Put(secretservicetest.Item{Label: "other", Attributes: map[string]string{
		ProjectAttribute: "/home/u/other", "sandbox:service": "gh:github.com",
	}, Value: []byte("other")})
	// A project whose path starts the same is another project.
	w.keyring.Put(secretservicetest.Item{Label: "prefix", Attributes: map[string]string{
		ProjectAttribute: project + "2", "sandbox:service": "gh:github.com",
	}, Value: []byte("other")})
	if got := w.search(t, map[string]string{"service": "gh:github.com"}); len(got) != 0 {
		t.Errorf("found %v", got)
	}
	if got := w.search(t, map[string]string{}); len(got) != 0 {
		t.Errorf("found %v", got)
	}
	// Nor can it name the project attribute to get at another's.
	if got := w.search(t, map[string]string{ProjectAttribute: "/home/u/other"}); len(got) != 0 {
		t.Errorf("found %v", got)
	}
	// What it stores replaces no one else's item.
	w.create(t, "mine", map[string]string{"service": "gh:github.com"}, []byte("mine"), true)
	if items := w.keyring.Items(); len(items) != 4 {
		t.Errorf("%d items", len(items))
	}
	for _, it := range w.keyring.Items() {
		if it.Label == "host gh" && string(it.Value) != "host" {
			t.Errorf("host item changed: %+v", it)
		}
	}
}

// A locked keyring is unlocked through the host's prompt, on first use.
func TestUnlocksOnTheHost(t *testing.T) {
	w := newWorldLocked(t, true)
	if n := w.keyring.Prompts(); n != 0 {
		t.Errorf("%d prompts at start", n)
	}
	item := w.create(t, "label", map[string]string{"k": "v"}, []byte("x"), true)
	if n := w.keyring.Prompts(); n != 1 {
		t.Errorf("%d prompts", n)
	}
	w.keyring.Lock()
	if s, err := w.get(item); err != nil || string(s.Value) != "x" {
		t.Errorf("get %+v %v", s, err)
	}
	if n := w.keyring.Prompts(); n != 2 {
		t.Errorf("%d prompts", n)
	}
}

func TestDismissedOnTheHost(t *testing.T) {
	w := newWorldLocked(t, true)
	w.keyring.DismissPrompts()
	err := w.call(collectionPath, collectionIface+".SearchItems", map[string]string{}).Err
	if err == nil || !strings.Contains(err.Error(), "dismissed on the host") {
		t.Errorf("%v", err)
	}
}

func TestNoHostService(t *testing.T) {
	if _, err := ConnectHost(t.Context(), secretservicetest.Bus(t), project); err != ErrNoHostService {
		t.Errorf("%v", err)
	}
}

// gh's logins are go-keyring items with service "gh:HOST", one per user;
// looked for only in an unlocked keyring.
func TestGhLogins(t *testing.T) {
	w := newWorld(t)
	host, err := ConnectHost(t.Context(), w.host, project)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if hosts, err := host.ghLogins(); err != nil || len(hosts) != 0 {
		t.Errorf("empty: %v %v", hosts, err)
	}
	for _, attrs := range []map[string]string{
		{"service": "gh:github.com", "username": ""},
		{"service": "gh:github.com", "username": "me"},
		{"service": "gh:ghe.example", "username": ""},
		{"service": "docker"},
	} {
		w.create(t, "x", attrs, []byte("t"), false)
	}
	// The host's own gh login isn't the sandbox's.
	w.keyring.Put(secretservicetest.Item{Attributes: map[string]string{"service": "gh:host.example"}})
	if hosts, err := host.ghLogins(); err != nil || !slices.Equal(hosts, []string{"ghe.example", "github.com"}) {
		t.Errorf("%v %v", hosts, err)
	}
	w.keyring.Lock()
	if hosts, err := host.ghLogins(); err != nil || len(hosts) != 0 || w.keyring.Prompts() != 0 {
		t.Errorf("locked: %v %v", hosts, err)
	}
}

// libsecret's own client: what secret-tool, Python keyring and GNOME apps
// use. It asks for an encrypted session first, then a plain one.
func TestSecretTool(t *testing.T) {
	tool, err := exec.LookPath("secret-tool")
	if err != nil {
		t.Skip("needs secret-tool")
	}
	w := newWorld(t)
	// Its stdout; secret-tool search prints attributes on stderr, which
	// goes in the error.
	runBoth := func(stdin string, args ...string) (string, string, error) {
		cmd := exec.Command(tool, args...)
		cmd.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS="+w.address)
		cmd.Stdin = strings.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		return string(out), stderr.String(), err
	}
	run := func(stdin string, args ...string) (string, error) {
		out, stderr, err := runBoth(stdin, args...)
		if err != nil {
			err = fmt.Errorf("%v: %s", err, stderr)
		}
		return out, err
	}

	value := "s3cret value"
	if _, err := run(value, "store", "--label=my token", "service", "demo", "user", "me"); err != nil {
		t.Fatal(err)
	}
	items := w.keyring.Items()
	if len(items) != 1 || string(items[0].Value) != value || items[0].Label != "sandbox proj: my token" ||
		items[0].Attributes["sandbox:service"] != "demo" || items[0].Attributes[ProjectAttribute] != project {
		t.Fatalf("on the host: %+v", items)
	}
	if out, err := run("", "lookup", "service", "demo"); err != nil || out != value {
		t.Errorf("lookup %q %v", out, err)
	}
	// What secret-tool search shows comes from the item's properties.
	out, attrs, err := runBoth("", "search", "--all", "service", "demo")
	if err != nil || !strings.Contains(out, "label = my token") || !strings.Contains(out, "secret = "+value) ||
		strings.Contains(out, "created = \n") ||
		!strings.Contains(attrs, "attribute.user = me") || strings.Contains(attrs, ProjectAttribute) {
		t.Errorf("search %q %q %v", out, attrs, err)
	}
	// A host item with the same attributes is no business of the sandbox.
	w.keyring.Put(secretservicetest.Item{Label: "host", Attributes: map[string]string{"service": "demo"}, Value: []byte("host")})
	if _, err := run("", "clear", "service", "demo"); err != nil {
		t.Fatal(err)
	}
	if items := w.keyring.Items(); len(items) != 1 || items[0].Label != "host" {
		t.Errorf("after clear: %+v", items)
	}
	if out, err := run("", "lookup", "service", "demo"); err == nil || out != "" {
		t.Errorf("lookup after clear %q %v", out, err)
	}
}

// Only plain sessions, refused the way libsecret then asks for one.
func TestOnlyPlainSessions(t *testing.T) {
	w := newWorld(t)
	err := w.call(servicePath, serviceIface+".OpenSession", "dh-ietf1024-sha256-aes128-cbc-pkcs7", dbus.MakeVariant([]byte{2})).Err
	var e dbus.Error
	if !errors.As(err, &e) || e.Name != "org.freedesktop.DBus.Error.NotSupported" {
		t.Errorf("%v", err)
	}
}
