// Package secretservice is secret-service-guard: an
// org.freedesktop.secrets D-Bus service for the sandbox, backed by the
// host's own Secret Service.
//
//	sandbox-bin secret-service-guard BUS_ADDRESS HOST_BUS_ADDRESS PROJECT
//
// It runs outside the sandbox, connected both to a private, ephemeral D-Bus
// bus the sandbox launcher starts just for this purpose and to the host's
// session bus, and keeps the sandbox's items in the host's default
// collection (gnome-keyring, KeePassXC, ...). The sandboxed process only
// ever sees the private bus, never the host's.
//
// Each project's items are its own: the guard marks every item with the
// project (ProjectAttribute) and adds that to every search, and prefixes the
// sandbox's attribute names (AttributePrefix), so a host program looking up
// its own credentials never finds one a sandbox stored.
//
// Any sandboxed process that stores credentials via libsecret/Secret Service
// gets real persistence instead of falling back to plaintext files - gh's
// go-keyring backend was the motivating case, but the same bus works for
// Docker credential helpers, `npm login`, Python `keyring`, and anything
// else that speaks the protocol.
//
// It implements just enough of the Secret Service spec for those clients:
// OpenSession("plain"), Unlock (always succeeds),
// Collection.SearchItems/CreateItem on a single fixed collection,
// Item.GetSecret/Delete. The Prompt object/signal dance is never triggered
// inside, because Unlock/CreateItem/Delete always return the null prompt
// path "/": when the host's keyring is locked, the guard has the host show
// its own unlock prompt, and the call waits for it.
//
// TODO: support libsecret clients (secret-tool, GNOME apps), then drop this
// note. libsecret opens only a dh-ietf1024-sha256-aes128-cbc-pkcs7 session
// (never "plain") and searches with Service.SearchItems, both missing here;
// done once `secret-tool store`/`lookup`/`clear` work against this guard.
package secretservice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/mgnsk/sandbox/internal/guard"
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

func invalidArgs(message string) *dbus.Error {
	return &dbus.Error{Name: "org.freedesktop.DBus.Error.InvalidArgs", Body: []any{message}}
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

// item is org.freedesktop.Secret.Item, one per host item the sandbox has
// been shown.
type item struct {
	host *Host
	path dbus.ObjectPath // On the host.
}

// GetSecret returns the item's secret, unencrypted.
func (it *item) GetSecret(session dbus.ObjectPath) (secret, *dbus.Error) {
	s, err := it.host.get(it.path)
	if err != nil {
		return secret{}, hostError(err)
	}
	return secret{Session: session, Parameters: []byte{}, Value: s.Value, ContentType: s.ContentType}, nil
}

// Delete deletes the item, with no prompt inside (the host may show one).
func (it *item) Delete() (dbus.ObjectPath, *dbus.Error) {
	if err := it.host.delete(it.path); err != nil {
		return "", hostError(err)
	}
	return nullPath, nil
}

// hostError is err from the host as an error for the sandbox: an item gone
// on the host is gone here too.
func hostError(err error) *dbus.Error {
	var e dbus.Error
	if errors.As(err, &e) {
		switch e.Name {
		case errNoSuchObject.Name, "org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.DBus.Error.UnknownMethod":
			return errNoSuchObject
		}
	}
	return dbus.MakeFailedError(err)
}

// collection is org.freedesktop.Secret.Collection: the single fixed
// default collection, the project's items on the host.
type collection struct {
	conn *dbus.Conn
	host *Host

	mu  sync.Mutex
	ids map[dbus.ObjectPath]int64 // Host item paths, by their number here.
}

// export exports a host item's object, once per process; its path here.
// Only paths the host returned for the project's own items get here.
func (c *collection) export(hostPath dbus.ObjectPath) (dbus.ObjectPath, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, ok := c.ids[hostPath]; ok {
		return itemPath(id), nil
	}
	id := int64(len(c.ids) + 1)
	path := itemPath(id)
	if err := c.conn.Export(&item{host: c.host, path: hostPath}, path, itemIface); err != nil {
		return "", err
	}
	if _, err := prop.Export(c.conn, path, prop.Map{itemIface: {}}); err != nil {
		return "", err
	}
	err := c.conn.Export(introspectable(itemIface,
		method("GetSecret", []string{"o"}, []string{"(oayays)"}),
		method("Delete", nil, []string{"o"}),
	), path, "org.freedesktop.DBus.Introspectable")
	if err != nil {
		return "", err
	}
	c.ids[hostPath] = id
	return path, nil
}

// SearchItems returns the items whose attributes include all of attrs.
func (c *collection) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	found, err := c.host.search(attrs)
	if err != nil {
		return nil, hostError(err)
	}
	paths := []dbus.ObjectPath{}
	for _, hostPath := range found {
		path, err := c.export(hostPath)
		if err != nil {
			return nil, dbus.MakeFailedError(err)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// CreateItem stores an item - with replace, in place of the one with exactly
// the same attributes - with no prompt inside (the host may show one).
func (c *collection) CreateItem(props map[string]dbus.Variant, s secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	label, ok := props[itemIface+".Label"].Value().(string)
	if !ok {
		return "", "", invalidArgs("no " + itemIface + ".Label")
	}
	attrs, ok := props[itemIface+".Attributes"].Value().(map[string]string)
	if !ok {
		return "", "", invalidArgs("no " + itemIface + ".Attributes")
	}
	hostPath, err := c.host.create(label, attrs, s.ContentType, s.Value, replace)
	if err != nil {
		return "", "", hostError(err)
	}
	path, err := c.export(hostPath)
	if err != nil {
		return "", "", dbus.MakeFailedError(err)
	}
	return path, nullPath, nil
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

// Export serves the Secret Service on conn, from host.
func Export(conn *dbus.Conn, host *Host) error {
	if err := conn.Export(&service{}, servicePath, serviceIface); err != nil {
		return err
	}
	// Collections deliberately empty, so go-keyring falls back to
	// aliases/default directly.
	_, err := prop.Export(conn, servicePath, prop.Map{serviceIface: {
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

	coll := &collection{conn: conn, host: host, ids: map[dbus.ObjectPath]int64{}}
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
	reply, err := conn.RequestName(serviceName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errors.New(serviceName + " is taken on this bus")
	}
	return nil
}

// Run serves until stopped, or until the bus - the sandbox's own, which
// the launcher stops with it - goes away.
func Run(ctx context.Context, busAddress, hostBusAddress, project string) error {
	host, err := ConnectHost(ctx, hostBusAddress, project)
	if errors.Is(err, ErrNoHostService) {
		return fmt.Errorf("%w: start one (gnome-keyring, KeePassXC, ...), or set guards.secretService.enable = false", err)
	}
	if err != nil {
		return err
	}
	defer host.Close()
	if hosts, err := host.ghLogins(); err == nil && len(hosts) > 0 {
		fmt.Fprintf(os.Stderr, "sandbox: WARNING: the host's keyring holds the project's gh tokens for %s, from a gh auth login inside -"+
			" readable by everything in the sandbox, and used around the GitHub guard's popups.\n"+
			"  Run `gh auth logout --hostname HOST` inside, revoke those tokens, and use guards.github.tokenCommand instead.\n",
			strings.Join(hosts, ", "))
	}
	conn, err := dbus.Connect(busAddress)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := Export(conn, host); err != nil {
		return err
	}
	if err := guard.Ready(struct{}{}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-conn.Context().Done():
	}
	return nil
}
