// Package notify shows the guards' approval popups as desktop notifications
// too, for a request made away from the terminal the sandbox runs on - by a
// GUI program inside, whose user isn't looking at that terminal.
//
// The launcher sends them, on the host's session bus
// (org.freedesktop.Notifications), which nothing in the sandbox reaches: its
// only bus is a private one. So a notification can't be answered or drawn
// by the sandbox, and what's in the notification area is the host's.
//
// A notification is an addition to the terminal popup, never a replacement:
// daemons differ in what they show and for how long, and none has to keep
// one on screen. Whichever is answered first settles the request.
package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/mgnsk/sandbox/internal/popup"
)

const (
	service = "org.freedesktop.Notifications"
	path    = dbus.ObjectPath("/org/freedesktop/Notifications")

	// How long the daemon has to answer a call: the launcher's terminal
	// relay waits on it.
	callTimeout = 2 * time.Second

	// Text up to this size goes into a notification whole. Daemons cut or
	// collapse long bodies, each in its own way and without a word, so
	// anything longer is cut here instead, where it can say so: the
	// notification then shows the start of the request - the guards put
	// what matters most first - and that the rest is on the terminal.
	maxBodyRunes = 400
	maxBodyLines = 10

	cutNote = "… cut here: the whole request is on the terminal the sandbox runs on."
)

// The reasons of NotificationClosed that matter here: 1 is expired, and
// anything unknown is taken as the daemon's own doing too.
const (
	closedDismissed = 2
	closedByCall    = 3
)

// Kind is what happened to a notification.
type Kind int

const (
	// Answered: the user picked one of its actions.
	Answered Kind = iota
	// Dismissed: the user closed it without picking one.
	Dismissed
	// Gone: the daemon took it away, unanswered - it expired, or the
	// daemon doesn't say why.
	Gone
)

// Event is what happened to the notification ID.
type Event struct {
	ID     uint32
	Kind   Kind
	Answer popup.Answer // Of an Answered one.
}

// Notifier shows requests as notifications of one sandbox.
type Notifier struct {
	conn   *dbus.Conn
	obj    dbus.BusObject
	title  string
	markup bool
	events chan Event
	done   chan struct{}
	once   sync.Once
}

// Connect connects to the notification daemon on the bus at address. title
// names the sandbox in each notification. It fails without a daemon that
// shows actions: a notification that can't be answered is only noise.
func Connect(address, title string) (*Notifier, error) {
	if address == "" {
		return nil, errors.New("no session bus")
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	conn, err := dbus.Connect(address)
	if err != nil {
		return nil, err
	}
	n := &Notifier{conn: conn, obj: conn.Object(service, path), title: title,
		events: make(chan Event, 16), done: make(chan struct{})}
	var capabilities []string
	if err := n.obj.CallWithContext(ctx, service+".GetCapabilities", 0).Store(&capabilities); err != nil {
		conn.Close()
		return nil, fmt.Errorf("no notification daemon: %w", err)
	}
	if !slices.Contains(capabilities, "actions") {
		conn.Close()
		return nil, errors.New("the notification daemon shows no actions")
	}
	n.markup = slices.Contains(capabilities, "body-markup")
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(service), dbus.WithMatchObjectPath(path)); err != nil {
		conn.Close()
		return nil, err
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	go n.relay(signals)
	return n, nil
}

// relay turns the daemon's signals into events.
func (n *Notifier) relay(signals <-chan *dbus.Signal) {
	for sig := range signals {
		var event Event
		switch sig.Name {
		case service + ".ActionInvoked":
			var key string
			if dbus.Store(sig.Body, &event.ID, &key) != nil {
				continue
			}
			event.Kind, event.Answer = Answered, popup.ParseAnswer(key)
		case service + ".NotificationClosed":
			var reason uint32
			if dbus.Store(sig.Body, &event.ID, &reason) != nil {
				continue
			}
			switch reason {
			case closedDismissed:
				event.Kind = Dismissed
			case closedByCall:
				// Ours.
				continue
			default:
				event.Kind = Gone
			}
		default:
			continue
		}
		select {
		case n.events <- event:
		case <-n.done:
			return
		}
	}
}

// Events are what happens to the notifications shown, every sandbox's on
// this bus included: the receiver goes by the ID.
func (n *Notifier) Events() <-chan Event { return n.events }

// escape makes text literal where the daemon reads the body as markup.
var escape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// content is a request's notification body, and whether that is the whole
// text: a longer one is cut to the size shown whole, and says so.
func content(text string) (body string, whole bool) {
	text = strings.TrimRight(popup.CleanText(text), "\n")
	if len([]rune(text)) <= maxBodyRunes && strings.Count(text, "\n") < maxBodyLines {
		return text, true
	}
	lines := strings.Split(text, "\n")
	if len(lines) > maxBodyLines {
		lines = lines[:maxBodyLines]
	}
	cut := []rune(strings.Join(lines, "\n"))
	if len(cut) > maxBodyRunes {
		cut = cut[:maxBodyRunes]
	}
	return strings.TrimRight(string(cut), "\n ") + "\n" + cutNote, false
}

// Show shows req; the notification's ID. It stays until it's answered or
// closed, as far as the daemon goes along: critical, and never expiring.
func (n *Notifier) Show(req popup.Request) (uint32, error) {
	body, _ := content(req.Text)
	if n.markup {
		body = escape.Replace(body)
	}
	// Deny first: where a daemon makes the first action the one a stray
	// click or key lands on.
	actions := []string{
		string(popup.No), "Deny",
		string(popup.Once), "Allow once",
		string(popup.Always), "Always in this sandbox",
	}
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(byte(2))}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var id uint32
	err := n.obj.CallWithContext(ctx, service+".Notify", 0,
		"sandbox", uint32(0), "", n.title+": "+popup.Clean(req.Name), body, actions, hints, int32(0)).Store(&id)
	return id, err
}

// Close takes the notification id away.
func (n *Notifier) Close(id uint32) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	_ = n.obj.CallWithContext(ctx, service+".CloseNotification", 0, id).Err
}

// Shutdown ends the connection.
func (n *Notifier) Shutdown() {
	n.once.Do(func() {
		close(n.done)
		n.conn.Close()
	})
}
