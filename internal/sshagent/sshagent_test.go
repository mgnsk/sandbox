package sshagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mgnsk/sandbox/internal/apiproxy/apiproxytest"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/popup"
)

// recorder is the user's real agent, recording what reaches it.
type recorder struct {
	agent.ExtendedAgent
	mu    sync.Mutex
	calls []string
}

func (r *recorder) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *recorder) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *recorder) List() ([]*agent.Key, error) { r.record("list"); return r.ExtendedAgent.List() }
func (r *recorder) SignWithFlags(k ssh.PublicKey, d []byte, f agent.SignatureFlags) (*ssh.Signature, error) {
	r.record("sign")
	return r.ExtendedAgent.SignWithFlags(k, d, f)
}
func (r *recorder) Add(k agent.AddedKey) error { r.record("add"); return r.ExtendedAgent.Add(k) }
func (r *recorder) Remove(k ssh.PublicKey) error {
	r.record("remove")
	return r.ExtendedAgent.Remove(k)
}
func (r *recorder) RemoveAll() error      { r.record("remove-all"); return r.ExtendedAgent.RemoveAll() }
func (r *recorder) Lock(p []byte) error   { r.record("lock"); return r.ExtendedAgent.Lock(p) }
func (r *recorder) Unlock(p []byte) error { r.record("unlock"); return r.ExtendedAgent.Unlock(p) }
func (r *recorder) Extension(t string, c []byte) ([]byte, error) {
	r.record("extension")
	return nil, agent.ErrExtensionUnsupported
}

type world struct {
	dir      string
	upstream *recorder
	key      ssh.PublicKey
	popups   *apiproxytest.Popups
}

// newWorld starts a real agent holding a key with comment.
func newWorld(t *testing.T, comment string) *world {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring().(agent.ExtendedAgent)
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: comment}); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	w := &world{dir: dir, upstream: &recorder{ExtendedAgent: keyring}, key: signer.PublicKey(), popups: &apiproxytest.Popups{}}
	serve(t, filepath.Join(dir, "agent.sock"), func(c net.Conn) {
		defer c.Close()
		agent.ServeAgent(w.upstream, c)
	})
	return w
}

func serve(t *testing.T, path string, handle func(net.Conn)) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go guard.Serve(ctx, ln, handle)
	t.Cleanup(cancel)
}

// guard starts an ssh-agent-guard in front of the agent; a client of it.
func (w *world) guard(t *testing.T) func() agent.ExtendedAgent {
	g := &Guard{Upstream: filepath.Join(w.dir, "agent.sock"), Ask: w.popups.Ask}
	path := filepath.Join(t.TempDir(), "guard.sock")
	serve(t, path, g.Handle)
	return func() agent.ExtendedAgent {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return agent.NewClient(conn)
	}
}

// sshsig is signed data as `ssh-keygen -Y sign -n namespace` hands it to
// the agent.
func sshsig(namespace string) []byte {
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace, Reserved, Hash string
		Digest                    []byte
	}{namespace, "", "sha512", make([]byte, 64)})...)
}

func TestListIsForwarded(t *testing.T) {
	w := newWorld(t, "me@laptop")
	keys, err := w.guard(t)().List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "me@laptop" {
		t.Fatalf("%v %v", keys, err)
	}
	if len(w.popups.Asked()) != 0 {
		t.Error("listing asked")
	}
}

func TestSignatures(t *testing.T) {
	w := newWorld(t, "me@laptop")
	client := w.guard(t)

	// Declined: never reaches the agent.
	if _, err := client().Sign(w.key, []byte("session")); err == nil {
		t.Error("declined signature made")
	}
	if slices.Contains(w.upstream.Calls(), "sign") {
		t.Error("declined signature reached the agent")
	}

	w.popups.Answer = popup.Once
	c := client()
	for range 2 {
		sig, err := c.Sign(w.key, []byte("session"))
		if err != nil || w.key.Verify([]byte("session"), sig) != nil {
			t.Fatalf("approved signature: %v", err)
		}
	}
	if n := len(w.popups.Asked()); n != 3 {
		t.Errorf("asked %d times", n)
	}

	// Always: across connections, for this guard only.
	w.popups.Answer = popup.Always
	client().Sign(w.key, []byte("session"))
	w.popups.Answer = popup.No
	if _, err := client().Sign(w.key, []byte("session")); err != nil {
		t.Errorf("always didn't cover the next: %v", err)
	}
	if _, err := w.guard(t)().Sign(w.key, []byte("session")); err == nil {
		t.Error("a new guard didn't ask")
	}
	if n := len(w.popups.Asked()); n != 5 {
		t.Errorf("asked %d times", n)
	}
}

// Commit and tag signatures, in git's namespace, go through without asking;
// other or malformed SSHSIG blobs ask like any other signature.
func TestCommitSignaturesSkipThePopup(t *testing.T) {
	w := newWorld(t, "me@laptop")
	client := w.guard(t)
	if _, err := client().Sign(w.key, sshsig("git")); err != nil {
		t.Fatal(err)
	}
	if len(w.popups.Asked()) != 0 {
		t.Error("a commit signature asked")
	}
	for _, data := range [][]byte{sshsig("file"), sshsig("gitx"), []byte("SSHSIG"), []byte("SSHSIG\xff\xff\xff\xffgit")} {
		if _, err := client().Sign(w.key, data); err == nil {
			t.Errorf("%q signed without asking", data)
		}
	}
	if n := len(w.popups.Asked()); n != 4 {
		t.Errorf("asked %d times", n)
	}
}

// Only listing and (gated) signing may reach the real agent. Everything
// else changes agent state the sandbox has no business touching - lock in
// particular would wedge the user's agent.
func TestEverythingElseIsRefused(t *testing.T) {
	w := newWorld(t, "me@laptop")
	w.popups.Answer = popup.Always
	c := w.guard(t)()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, err := range map[string]error{
		"add":        c.Add(agent.AddedKey{PrivateKey: priv}),
		"remove":     c.Remove(w.key),
		"remove-all": c.RemoveAll(),
		"lock":       c.Lock([]byte("pw")),
		"unlock":     c.Unlock([]byte("pw")),
		"extension":  second(c.Extension("session-bind@openssh.com", nil)),
	} {
		if err == nil {
			t.Errorf("%s went through", name)
		}
	}
	if calls := w.upstream.Calls(); len(calls) != 0 {
		t.Errorf("reached the agent: %v", calls)
	}
	if len(w.popups.Asked()) != 0 {
		t.Error("asked")
	}
}

func second[T any](_ T, err error) error { return err }

func TestPopupText(t *testing.T) {
	w := newWorld(t, "\x1b[31mred"+strings.Repeat("a", 300))
	c := w.guard(t)()
	// The comment comes from an earlier listing.
	c.Sign(w.key, []byte("session"))
	c.List()
	c.Sign(w.key, []byte("session"))
	asked := w.popups.Asked()
	if len(asked) != 2 {
		t.Fatalf("asked %+v", asked)
	}
	if !strings.Contains(asked[0].Text, "  comment:  unknown\n") {
		t.Errorf("before listing: %q", asked[0].Text)
	}
	wd, _ := os.Getwd()
	text := asked[1].Text
	for _, want := range []string{
		"Allow SSH agent to sign?\n\n",
		"  cwd:      " + wd + "\n",
		"  command:  " + os.Args[0],
		"  comment:  ?[31mred" + strings.Repeat("a", 192) + "…\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%q not in %q", want, text)
		}
	}
	if asked[1].Name != "ssh-agent-guard" {
		t.Errorf("name %q", asked[1].Name)
	}
}

func TestUnreachableAgentClosesTheClient(t *testing.T) {
	g := &Guard{Upstream: filepath.Join(t.TempDir(), "nope.sock")}
	path := filepath.Join(t.TempDir(), "guard.sock")
	serve(t, path, g.Handle)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("not closed")
	}
}
