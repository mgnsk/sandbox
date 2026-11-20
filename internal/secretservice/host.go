package secretservice

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	// ProjectAttribute is on every host item a sandbox stores: the project's
	// path. The guard adds it to every search and creation, so a sandbox
	// sees only its own project's items.
	ProjectAttribute = "sandbox-project"
	// AttributePrefix is in front of each of the sandbox's own attribute
	// names on the host. Without it a sandbox could plant an item a host
	// program finds by its own attributes - say {service: gh:github.com} -
	// and uses as its credential.
	AttributePrefix = "sandbox:"

	promptIface  = "org.freedesktop.Secret.Prompt"
	sessionIface = "org.freedesktop.Secret.Session"

	// How long the host's unlock (or other) prompt waits for an answer.
	promptTimeout = 2 * time.Minute
)

// ErrNoHostService is the host session bus without a Secret Service,
// running or activatable.
var ErrNoHostService = errors.New("no Secret Service (" + serviceName + ") on the host's session bus")

// Host is the host's Secret Service, as one project's store: items in its
// default collection, marked with ProjectAttribute. It unlocks the
// collection when it needs to, which shows the host's own prompt.
type Host struct {
	ctx     context.Context
	conn    *dbus.Conn
	project string
	prompts sync.Mutex // One host prompt at a time.
}

// ConnectHost connects to the host's session bus at address, as project's
// store; ErrNoHostService without a Secret Service there.
func ConnectHost(ctx context.Context, address, project string) (*Host, error) {
	conn, err := dbus.Connect(address)
	if err != nil {
		return nil, fmt.Errorf("the host's session bus: %w", err)
	}
	if err := available(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return &Host{ctx: ctx, conn: conn, project: project}, nil
}

// available checks the Secret Service runs, or is started on demand.
func available(conn *dbus.Conn) error {
	bus := conn.BusObject()
	var running bool
	if err := bus.Call("org.freedesktop.DBus.NameHasOwner", 0, serviceName).Store(&running); err != nil {
		return err
	}
	if running {
		return nil
	}
	var activatable []string
	if err := bus.Call("org.freedesktop.DBus.ListActivatableNames", 0).Store(&activatable); err != nil {
		return err
	}
	if slices.Contains(activatable, serviceName) {
		return nil
	}
	return ErrNoHostService
}

// Close closes the connection.
func (h *Host) Close() error { return h.conn.Close() }

func (h *Host) object(path dbus.ObjectPath) dbus.BusObject {
	return h.conn.Object(serviceName, path)
}

func (h *Host) call(path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	return h.object(path).CallWithContext(h.ctx, method, 0, args...)
}

// hostAttributes are attrs as stored on the host: prefixed, and marked as
// the project's.
func (h *Host) hostAttributes(attrs map[string]string) map[string]string {
	out := map[string]string{ProjectAttribute: h.project}
	for k, v := range attrs {
		out[AttributePrefix+k] = v
	}
	return out
}

// collection is the host's default collection; with unlock, unlocked, after
// the host's prompt if it's locked. Without unlock, "" if it's locked.
func (h *Host) collection(unlock bool) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	if err := h.call(servicePath, serviceIface+".ReadAlias", "default").Store(&path); err != nil {
		return "", err
	}
	if path == nullPath {
		return "", errors.New("the host's Secret Service has no default collection")
	}
	locked, err := h.object(path).GetProperty(collectionIface + ".Locked")
	if err != nil {
		return "", err
	}
	if l, _ := locked.Value().(bool); !l {
		return path, nil
	}
	if !unlock {
		return "", nil
	}
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := h.call(servicePath, serviceIface+".Unlock", []dbus.ObjectPath{path}).Store(&unlocked, &prompt); err != nil {
		return "", err
	}
	if _, err := h.prompt(prompt); err != nil {
		return "", fmt.Errorf("unlocking the host's keyring: %w", err)
	}
	return path, nil
}

// prompt shows the host's prompt at path, if any, and waits for its answer;
// its result.
func (h *Host) prompt(path dbus.ObjectPath) (dbus.Variant, error) {
	if path == nullPath || path == "" {
		return dbus.Variant{}, nil
	}
	h.prompts.Lock()
	defer h.prompts.Unlock()
	match := []dbus.MatchOption{
		dbus.WithMatchObjectPath(path),
		dbus.WithMatchInterface(promptIface),
		dbus.WithMatchMember("Completed"),
	}
	if err := h.conn.AddMatchSignal(match...); err != nil {
		return dbus.Variant{}, err
	}
	defer h.conn.RemoveMatchSignal(match...)
	signals := make(chan *dbus.Signal, 8)
	h.conn.Signal(signals)
	defer h.conn.RemoveSignal(signals)

	if err := h.call(path, promptIface+".Prompt", "").Err; err != nil {
		return dbus.Variant{}, err
	}
	ctx, cancel := context.WithTimeout(h.ctx, promptTimeout)
	defer cancel()
	for {
		select {
		case s := <-signals:
			if s.Path != path || s.Name != promptIface+".Completed" || len(s.Body) != 2 {
				continue
			}
			if dismissed, _ := s.Body[0].(bool); dismissed {
				return dbus.Variant{}, errors.New("dismissed on the host")
			}
			result, _ := s.Body[1].(dbus.Variant)
			return result, nil
		case <-ctx.Done():
			_ = h.object(path).Call(promptIface+".Dismiss", 0).Err
			return dbus.Variant{}, errors.New("no answer to the host's prompt")
		}
	}
}

// session opens a plain session, for one transfer of a secret: the host's
// bus is the user's own, which the sandbox can't reach. It's closed with
// the returned func.
func (h *Host) session() (dbus.ObjectPath, func(), error) {
	var output dbus.Variant
	var path dbus.ObjectPath
	if err := h.call(servicePath, serviceIface+".OpenSession", "plain", dbus.MakeVariant("")).Store(&output, &path); err != nil {
		return "", nil, err
	}
	return path, func() { _ = h.object(path).Call(sessionIface+".Close", 0).Err }, nil
}

// search returns the project's items whose attributes include attrs.
func (h *Host) search(attrs map[string]string) ([]dbus.ObjectPath, error) {
	coll, err := h.collection(true)
	if err != nil {
		return nil, err
	}
	var items []dbus.ObjectPath
	err = h.call(coll, collectionIface+".SearchItems", h.hostAttributes(attrs)).Store(&items)
	return items, err
}

// create stores an item - with replace, in place of the project's one with
// exactly the same attributes; its host path.
func (h *Host) create(label string, attrs map[string]string, contentType string, value []byte, replace bool) (dbus.ObjectPath, error) {
	coll, err := h.collection(true)
	if err != nil {
		return "", err
	}
	session, closeSession, err := h.session()
	if err != nil {
		return "", err
	}
	defer closeSession()
	props := map[string]dbus.Variant{
		itemIface + ".Label":      dbus.MakeVariant(h.labelPrefix() + label),
		itemIface + ".Attributes": dbus.MakeVariant(h.hostAttributes(attrs)),
	}
	var item, prompt dbus.ObjectPath
	err = h.call(coll, collectionIface+".CreateItem", props, secret{session, []byte{}, value, contentType}, replace).Store(&item, &prompt)
	if err != nil {
		return "", err
	}
	if prompt != nullPath {
		result, err := h.prompt(prompt)
		if err != nil {
			return "", err
		}
		if item, _ = result.Value().(dbus.ObjectPath); item == "" || item == nullPath {
			return "", errors.New("the host created no item")
		}
	}
	return item, nil
}

// get returns an item's secret.
func (h *Host) get(item dbus.ObjectPath) (secret, error) {
	if _, err := h.collection(true); err != nil {
		return secret{}, err
	}
	session, closeSession, err := h.session()
	if err != nil {
		return secret{}, err
	}
	defer closeSession()
	var s secret
	err = h.call(item, itemIface+".GetSecret", session).Store(&s)
	return s, err
}

// delete deletes an item.
func (h *Host) delete(item dbus.ObjectPath) error {
	if _, err := h.collection(true); err != nil {
		return err
	}
	var prompt dbus.ObjectPath
	if err := h.call(item, itemIface+".Delete").Store(&prompt); err != nil {
		return err
	}
	_, err := h.prompt(prompt)
	return err
}

// ghLogins lists the hosts gh stored a token for: go-keyring's items, with
// service "gh:HOST". Only looked for in an unlocked keyring, so that a
// sandbox's start shows no prompt.
func (h *Host) ghLogins() ([]string, error) {
	coll, err := h.collection(false)
	if err != nil || coll == "" {
		return nil, err
	}
	var items []dbus.ObjectPath
	if err := h.call(coll, collectionIface+".SearchItems", h.hostAttributes(nil)).Store(&items); err != nil {
		return nil, err
	}
	var hosts []string
	for _, item := range items {
		v, err := h.object(item).GetProperty(itemIface + ".Attributes")
		if err != nil {
			return nil, err
		}
		attrs, _ := v.Value().(map[string]string)
		if host, ok := strings.CutPrefix(attrs[AttributePrefix+"service"], "gh:"); ok && !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	slices.Sort(hosts)
	return hosts, nil
}

// itemProperties are an item's properties, as the sandbox sees them.
type itemProperties struct {
	label             string
	attributes        map[string]string
	created, modified uint64
}

// properties reads an item's properties: its label and attributes as the
// sandbox stored them. A locked item's are read without unlocking - the
// host has them - so listing items shows no prompt.
func (h *Host) properties(item dbus.ObjectPath) (itemProperties, error) {
	var all map[string]dbus.Variant
	if err := h.call(item, "org.freedesktop.DBus.Properties.GetAll", itemIface).Store(&all); err != nil {
		return itemProperties{}, err
	}
	var p itemProperties
	label, _ := all["Label"].Value().(string)
	p.label = strings.TrimPrefix(label, h.labelPrefix())
	attrs, _ := all["Attributes"].Value().(map[string]string)
	p.attributes = map[string]string{}
	for k, v := range attrs {
		if k, ok := strings.CutPrefix(k, AttributePrefix); ok {
			p.attributes[k] = v
		}
	}
	p.created, _ = all["Created"].Value().(uint64)
	p.modified, _ = all["Modified"].Value().(uint64)
	return p, nil
}

// labelPrefix is in front of the label of every item a sandbox stores.
func (h *Host) labelPrefix() string {
	return "sandbox " + filepath.Base(h.project) + ": "
}
