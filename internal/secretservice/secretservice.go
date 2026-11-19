// Package secretservice is secret-service-guard: a fake
// org.freedesktop.secrets D-Bus service for the sandbox.
//
//	secret-service-guard BUS_ADDRESS DATABASE READY_FILE
//
// It runs outside the sandbox, connected to a private, ephemeral D-Bus bus
// the sandbox launcher starts just for this purpose, and persists secrets in
// a sqlite database on the host; the sandboxed process only ever sees the
// bus socket, never the database file.
//
// Any sandboxed process that stores credentials via libsecret/Secret Service
// gets real persistence instead of falling back to plaintext files - gh's
// go-keyring backend was the motivating case, but the same bus works for
// Docker credential helpers, `npm login`, Python `keyring`, and anything
// else that speaks the protocol.
//
// It implements just enough of the Secret Service spec for those clients:
// OpenSession("plain"), Unlock (always succeeds, no master password),
// Collection.SearchItems/CreateItem on a single fixed collection,
// Item.GetSecret/Delete. The Prompt object/signal dance is never triggered,
// because Unlock/CreateItem/Delete always return the null prompt path "/".
//
// TODO: support libsecret clients (secret-tool, GNOME apps), then drop this
// note. libsecret opens only a dh-ietf1024-sha256-aes128-cbc-pkcs7 session
// (never "plain") and searches with Service.SearchItems, both missing here;
// done once `secret-tool store`/`lookup`/`clear` work against this guard.
package secretservice

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/mgnsk/sandbox/internal/cover"
)

const (
	serviceName    = "org.freedesktop.secrets"
	servicePath    = "/org/freedesktop/secrets"
	collectionPath = "/org/freedesktop/secrets/aliases/default"
	itemPathPrefix = "/org/freedesktop/secrets/item/"
	sessionPrefix  = "/org/freedesktop/secrets/session/s"
	nullPath       = dbus.ObjectPath("/")

	serviceIface    = "org.freedesktop.Secret.Service"
	collectionIface = "org.freedesktop.Secret.Collection"
	itemIface       = "org.freedesktop.Secret.Item"
)

var errNoSuchObject = &dbus.Error{
	Name: "org.freedesktop.Secret.Error.NoSuchObject",
	Body: []any{"no such item"},
}

// secret is the spec's Secret struct, (oayays), always unencrypted.
type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func itemPath(id int64) dbus.ObjectPath {
	return dbus.ObjectPath(itemPathPrefix + strconv.FormatInt(id, 10))
}

func failed(err error) *dbus.Error {
	return dbus.MakeFailedError(err)
}

// introspectable describes an object with one interface of methods.
func introspectable(iface string, methods ...introspect.Method) introspect.Introspectable {
	return introspect.NewIntrospectable(&introspect.Node{
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{Name: iface, Methods: methods},
		},
	})
}

func method(name string, in, out []string) introspect.Method {
	var args []introspect.Arg
	for i, t := range in {
		args = append(args, introspect.Arg{Name: "arg" + strconv.Itoa(i), Type: t, Direction: "in"})
	}
	for i, t := range out {
		args = append(args, introspect.Arg{Name: "out" + strconv.Itoa(i), Type: t, Direction: "out"})
	}
	return introspect.Method{Name: name, Args: args}
}

// item is org.freedesktop.Secret.Item, one per stored item.
type item struct {
	store *store
	id    int64
}

// GetSecret returns the item's secret, unencrypted.
func (it *item) GetSecret(session dbus.ObjectPath) (secret, *dbus.Error) {
	contentType, value, err := it.store.get(it.id)
	if errors.Is(err, sql.ErrNoRows) {
		return secret{}, errNoSuchObject
	}
	if err != nil {
		return secret{}, failed(err)
	}
	return secret{Session: session, Parameters: []byte{}, Value: value, ContentType: contentType}, nil
}

// Delete deletes the item, with no prompt.
func (it *item) Delete() (dbus.ObjectPath, *dbus.Error) {
	if err := it.store.delete(it.id); err != nil {
		return "", failed(err)
	}
	return nullPath, nil
}

// collection is org.freedesktop.Secret.Collection: the single fixed
// default collection.
type collection struct {
	conn     *dbus.Conn
	store    *store
	mu       sync.Mutex
	exported map[int64]bool
}

// export exports a stored item's object, once per process.
func (c *collection) export(id int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exported[id] {
		return nil
	}
	path := itemPath(id)
	if err := c.conn.Export(&item{store: c.store, id: id}, path, itemIface); err != nil {
		return err
	}
	if _, err := prop.Export(c.conn, path, prop.Map{itemIface: {}}); err != nil {
		return err
	}
	err := c.conn.Export(introspectable(itemIface,
		method("GetSecret", []string{"o"}, []string{"(oayays)"}),
		method("Delete", nil, []string{"o"}),
	), path, "org.freedesktop.DBus.Introspectable")
	if err != nil {
		return err
	}
	c.exported[id] = true
	return nil
}

// SearchItems returns the items whose attributes include all of attrs.
func (c *collection) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	rows, err := c.store.rows()
	if err != nil {
		return nil, failed(err)
	}
	paths := []dbus.ObjectPath{}
	for _, r := range rows {
		if !includes(r.attributes, attrs) {
			continue
		}
		if err := c.export(r.id); err != nil {
			return nil, failed(err)
		}
		paths = append(paths, itemPath(r.id))
	}
	return paths, nil
}

func includes(have, want map[string]string) bool {
	for k, v := range want {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// CreateItem stores an item - with replace, in place of the one with exactly
// the same attributes - with no prompt.
func (c *collection) CreateItem(props map[string]dbus.Variant, s secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	label, ok := props[itemIface+".Label"].Value().(string)
	if !ok {
		return "", "", &dbus.Error{Name: "org.freedesktop.DBus.Error.InvalidArgs", Body: []any{"no " + itemIface + ".Label"}}
	}
	attrs, ok := props[itemIface+".Attributes"].Value().(map[string]string)
	if !ok {
		return "", "", &dbus.Error{Name: "org.freedesktop.DBus.Error.InvalidArgs", Body: []any{"no " + itemIface + ".Attributes"}}
	}
	id, err := c.store.upsert(label, attrs, s.ContentType, s.Value, replace)
	if err != nil {
		return "", "", failed(err)
	}
	if err := c.export(id); err != nil {
		return "", "", failed(err)
	}
	return itemPath(id), nullPath, nil
}

// service is org.freedesktop.Secret.Service: always unlocked, no password.
type service struct {
	sessions atomic.Int64
}

// OpenSession opens a "plain" (unencrypted) session.
func (s *service) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	n := s.sessions.Add(1)
	return dbus.MakeVariant(""), dbus.ObjectPath(sessionPrefix + strconv.FormatInt(n, 10)), nil
}

// Unlock reports everything as already unlocked, with no prompt.
func (s *service) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	if objects == nil {
		objects = []dbus.ObjectPath{}
	}
	return objects, nullPath, nil
}

func serve(busAddress, dbPath, readyPath string) error {
	st, err := openStore(dbPath)
	if err != nil {
		return err
	}
	conn, err := dbus.Connect(busAddress)
	if err != nil {
		return err
	}

	if err := conn.Export(&service{}, servicePath, serviceIface); err != nil {
		return err
	}
	// Collections deliberately empty, so go-keyring falls back to
	// aliases/default directly.
	_, err = prop.Export(conn, servicePath, prop.Map{serviceIface: {
		"Collections": {Value: []dbus.ObjectPath{}, Emit: prop.EmitFalse},
	}})
	if err != nil {
		return err
	}
	err = conn.Export(introspectable(serviceIface,
		method("OpenSession", []string{"s", "v"}, []string{"v", "o"}),
		method("Unlock", []string{"ao"}, []string{"ao", "o"}),
	), servicePath, "org.freedesktop.DBus.Introspectable")
	if err != nil {
		return err
	}

	coll := &collection{conn: conn, store: st, exported: map[int64]bool{}}
	if err := conn.Export(coll, collectionPath, collectionIface); err != nil {
		return err
	}
	if _, err := prop.Export(conn, collectionPath, prop.Map{collectionIface: {}}); err != nil {
		return err
	}
	err = conn.Export(introspectable(collectionIface,
		method("SearchItems", []string{"a{ss}"}, []string{"ao"}),
		method("CreateItem", []string{"a{sv}", "(oayays)", "b"}, []string{"o", "o"}),
	), collectionPath, "org.freedesktop.DBus.Introspectable")
	if err != nil {
		return err
	}
	rows, err := st.rows()
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := coll.export(r.id); err != nil {
			return err
		}
	}

	if _, err := conn.RequestName(serviceName, 0); err != nil {
		return err
	}
	if err := os.WriteFile(readyPath, nil, 0o666); err != nil {
		return err
	}
	<-conn.Context().Done()
	return errors.New("the bus went away")
}

// Main serves on the bus at argv[1], the store at argv[2], creating argv[3]
// once ready.
func Main(argv []string) int {
	if len(argv) != 4 {
		fmt.Fprintln(os.Stderr, "usage: secret-service-guard BUS_ADDRESS DATABASE READY_FILE")
		return 2
	}
	cover.DieOnSignals()
	if err := serve(argv[1], argv[2], argv[3]); err != nil {
		fmt.Fprintf(os.Stderr, "secret-service-guard: %v\n", err)
		return 1
	}
	return 0
}
