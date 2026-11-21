package sshagent

import (
	"bytes"
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
	"golang.org/x/crypto/ssh/knownhosts"

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

// guard starts an ssh-agent-guard in front of the agent, with signing as
// git's signing keys; a client of it.
func (w *world) guard(t *testing.T, signing ...ssh.PublicKey) func() agent.ExtendedAgent {
	g := &Guard{Upstream: filepath.Join(w.dir, "agent.sock"), Ask: w.popups.Ask, SigningKeys: signing}
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

// Commit and tag signatures, in git's namespace and with git's signing key,
// go through without asking; other or malformed SSHSIG blobs ask like any
// other signature.
func TestCommitSignaturesSkipThePopup(t *testing.T) {
	w := newWorld(t, "me@laptop")
	client := w.guard(t, w.key)
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
		"extension":  second(c.Extension("other@example.com", nil)),
		"bad bind":   second(c.Extension(sessionBind, nil)),
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

// Only with git's signing key: any other key the agent holds - one meant
// for logging in somewhere - would otherwise sign commits as the user,
// unasked.
func TestCommitSignaturesWithAnotherKeyAsk(t *testing.T) {
	w := newWorld(t, "login key")
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	signing, _ := ssh.NewSignerFromKey(other)
	for name, client := range map[string]func() agent.ExtendedAgent{
		"no signing key":      w.guard(t),
		"another signing key": w.guard(t, signing.PublicKey()),
	} {
		if _, err := client().Sign(w.key, sshsig("git")); err == nil {
			t.Errorf("%s: signed without asking", name)
		}
	}
	asked := w.popups.Asked()
	if len(asked) != 2 || !strings.Contains(asked[0].Text, "  signing:  a git commit or tag, with a key that isn't your signing key\n") {
		t.Errorf("asked %+v", asked)
	}
}

// The popup says what kind of thing is signed, by the form its verifier
// takes it in.
func TestSigned(t *testing.T) {
	login := ssh.Marshal(struct {
		Session               []byte
		Type                  byte
		User, Service, Method string
		HasSig                bool
		Algo                  string
		Key                   []byte
	}{[]byte("session id"), msgUserauthRequest, "git", "ssh-connection", "publickey", true, "ssh-ed25519", []byte("key")})
	for want, data := range map[string][]byte{
		`an ssh login as "git", to a server the guard can't know`:     login,
		`a signature for "file" (ssh-keygen -Y sign)`:                 sshsig("file"),
		`a git commit or tag, with a key that isn't your signing key`: sshsig("git"),
		"data of no known kind (7 bytes)":                             []byte("session"),
		"data of no known kind (6 bytes)":                             []byte("SSHSIG"),
	} {
		if got := signed(data); got != want {
			t.Errorf("%q, want %q", got, want)
		}
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
		"  signing:  data of no known kind (7 bytes)\n",
		"  key:      " + ssh.FingerprintSHA256(w.key) + "\n",
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

// hostKey is a server's host key.
func hostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// bindMsg is a session-bind's contents as ssh sends them: host's key and
// its signature over session.
func bindMsg(t *testing.T, host ssh.Signer, session []byte, forwarding bool) []byte {
	t.Helper()
	sig, err := host.Sign(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(struct {
		HostKey, Session, Signature []byte
		Forwarding                  bool
	}{host.PublicKey().Marshal(), session, ssh.Marshal(sig), forwarding})
}

// loginData is what ssh asks the agent to sign to log in as user in
// session.
func loginData(session []byte, user string) []byte {
	return ssh.Marshal(struct {
		Session               []byte
		Type                  byte
		User, Service, Method string
		HasSig                bool
		Algo                  string
		Key                   []byte
	}{session, msgUserauthRequest, user, "ssh-connection", "publickey", true, "ssh-ed25519", []byte("key")})
}

// knownHosts writes lines as a known_hosts file.
func knownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func authorized(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// A login in a session the client bound names its server, by the host key
// that signed the session; any other login asks as before.
func TestSessionBindNamesTheServer(t *testing.T) {
	w := newWorld(t, "me@laptop")
	github, unknown := hostKey(t), hostKey(t)
	g := &Guard{
		Upstream:   filepath.Join(w.dir, "agent.sock"),
		Ask:        w.popups.Ask,
		KnownHosts: knownHosts(t, "# a comment", "github.com,140.82.121.4 "+authorized(github.PublicKey())),
	}
	path := filepath.Join(t.TempDir(), "guard.sock")
	serve(t, path, g.Handle)
	client := func() agent.ExtendedAgent {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return agent.NewClient(conn)
	}

	c := client()
	if _, err := c.Extension(sessionBind, bindMsg(t, github, []byte("gh session"), false)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Extension(sessionBind, bindMsg(t, unknown, []byte("other session"), false)); err != nil {
		t.Fatal(err)
	}
	// Rebinding a session, or with a signature not over it, is refused.
	if _, err := c.Extension(sessionBind, bindMsg(t, unknown, []byte("gh session"), false)); err == nil {
		t.Error("rebound a session")
	}
	forged := bindMsg(t, github, []byte("real"), false)
	forged = bytes.Replace(forged, []byte("real"), []byte("fake"), 1)
	if _, err := c.Extension(sessionBind, forged); err == nil {
		t.Error("bound with a signature over another session")
	}
	c.Sign(w.key, loginData([]byte("gh session"), "git"))
	c.Sign(w.key, loginData([]byte("other session"), "me"))
	c.Sign(w.key, loginData([]byte("fake"), "git"))
	// Binds are the connection's own.
	client().Sign(w.key, loginData([]byte("gh session"), "git"))

	asked := w.popups.Asked()
	want := []string{
		"  signing:  an ssh login as \"git\"\n  server:   github.com, 140.82.121.4, by its host key in your known_hosts\n  always:   covers logins to this server alone\n  key:      ",
		"  signing:  an ssh login as \"me\"\n  server:   a host whose key isn't in your known_hosts (" + ssh.FingerprintSHA256(unknown.PublicKey()) + ")\n  always:   covers logins to this server alone\n  key:      ",
		"  signing:  an ssh login as \"git\", to a server the guard can't know\n  key:      ",
		"  signing:  an ssh login as \"git\", to a server the guard can't know\n  key:      ",
	}
	if len(asked) != len(want) {
		t.Fatalf("asked %d times", len(asked))
	}
	for i, w := range want {
		if !strings.Contains(asked[i].Text, w) {
			t.Errorf("%d: %q not in %q", i, w, asked[i].Text)
		}
	}
	if calls := w.upstream.Calls(); slices.Contains(calls, "extension") {
		t.Errorf("session-bind reached the agent: %v", calls)
	}
}

// A login through a forwarded agent says where the agent was forwarded.
func TestSessionBindForwarded(t *testing.T) {
	jump, dest := hostKey(t), hostKey(t)
	g := &Guard{KnownHosts: knownHosts(t, "jump "+authorized(jump.PublicKey()), "dest "+authorized(dest.PublicKey()))}
	a := &gated{guard: g}
	for _, b := range [][]byte{bindMsg(t, jump, []byte("1"), true), bindMsg(t, dest, []byte("2"), false)} {
		if err := a.addBind(b); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := a.describe(loginData([]byte("2"), "git"))
	want := "  signing:  an ssh login as \"git\"\n" +
		"  server:   dest, by its host key in your known_hosts\n" +
		"  through:  your agent, forwarded to jump, by its host key in your known_hosts\n" +
		"  always:   covers logins to this server alone\n"
	if got != want {
		t.Errorf("%q\nwant %q", got, want)
	}
}

func TestServerName(t *testing.T) {
	gh, revoked, hashedOnly := hostKey(t), hostKey(t), hostKey(t)
	fp := ssh.FingerprintSHA256
	g := &Guard{KnownHosts: knownHosts(t,
		knownhosts.HashHostname("github.com")+" "+authorized(gh.PublicKey()),
		knownhosts.HashHostname("[git.example]:2222")+",!evil.com "+authorized(hashedOnly.PublicKey()),
		"@revoked * "+authorized(revoked.PublicKey()),
		"old.example "+authorized(revoked.PublicKey()),
		"garbage line that isn't one",
	)}
	for _, c := range []struct {
		key     ssh.Signer
		claimed string
		want    string
	}{
		{gh, "github.com", "github.com, by its host key in your known_hosts"},
		// Only a name whose entry holds the key.
		{gh, "evil.com", "a host with a hashed entry in your known_hosts (" + fp(gh.PublicKey()) + ")"},
		{gh, "", "a host with a hashed entry in your known_hosts (" + fp(gh.PublicKey()) + ")"},
		{hashedOnly, "[git.example]:2222", "[git.example]:2222, by its host key in your known_hosts"},
		{hashedOnly, "git.example", "a host with a hashed entry in your known_hosts (" + fp(hashedOnly.PublicKey()) + ")"},
		{revoked, "old.example", "a host whose key your known_hosts REVOKES (" + fp(revoked.PublicKey()) + ")"},
	} {
		if got := g.server(c.key.PublicKey(), c.claimed); got != c.want {
			t.Errorf("%s claimed %q: %q, want %q", fp(c.key.PublicKey()), c.claimed, got, c.want)
		}
	}
	if got, want := (&Guard{KnownHosts: filepath.Join(t.TempDir(), "none")}).server(gh.PublicKey(), "github.com"),
		"a host whose key isn't in your known_hosts ("+fp(gh.PublicKey())+")"; got != want {
		t.Errorf("no file: %q", got)
	}
}

func TestSSHDestination(t *testing.T) {
	for want, args := range map[string][]string{
		"github.com":         {"ssh", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-receive-pack 'o/r.git'"},
		"[git.example]:2222": {"/nix/store/x/bin/ssh", "-x", "-p", "2222", "git@git.example", "git-upload-pack"},
		"[a.example]:2200":   {"ssh", "-oPort=2200", "-v4", "a.example"},
		"[b.example]:7999":   {"ssh", "ssh://git@b.example:7999/o/r.git"},
		"c.example":          {"ssh", "-i", "key", "--", "c.example"},
		"d.example":          {"ssh", "-p22", "-Avl", "me", "d.example"},
		"":                   {"git", "push", "github.com"},
		" ":                  nil,
	} {
		if want == " " {
			want = ""
		}
		if got := sshDestination(args); got != want {
			t.Errorf("%q: %q, want %q", args, got, want)
		}
	}
}

// "Always" for a login to one server covers later logins to it alone:
// neither another server's, nor one through a forwarded agent, nor any
// signature without a bind - and "always" for those covers no server's.
func TestAlwaysIsScopedToTheServer(t *testing.T) {
	w := newWorld(t, "me@laptop")
	github, other := hostKey(t), hostKey(t)
	client := w.guard(t)
	login := func(host ssh.Signer, session string, forwardedFrom ssh.Signer) error {
		c := client()
		if forwardedFrom != nil {
			if _, err := c.Extension(sessionBind, bindMsg(t, forwardedFrom, []byte("fwd "+session), true)); err != nil {
				t.Fatal(err)
			}
		}
		if host != nil {
			if _, err := c.Extension(sessionBind, bindMsg(t, host, []byte(session), false)); err != nil {
				t.Fatal(err)
			}
		}
		_, err := c.Sign(w.key, loginData([]byte(session), "git"))
		return err
	}

	w.popups.Answer = popup.Always
	if err := login(github, "1", nil); err != nil {
		t.Fatal(err)
	}
	w.popups.Answer = popup.No
	if err := login(github, "2", nil); err != nil {
		t.Errorf("always didn't cover the same server: %v", err)
	}
	if n := len(w.popups.Asked()); n != 1 {
		t.Errorf("asked %d times", n)
	}
	for name, err := range map[string]error{
		"another server":       login(other, "3", nil),
		"through a forward":    login(github, "4", other),
		"an unbound login":     login(nil, "5", nil),
		"another kind of data": second(client().Sign(w.key, []byte("data"))),
	} {
		if err == nil {
			t.Errorf("%s went through", name)
		}
	}

	// Always for unbound signatures covers no server.
	w.popups.Answer = popup.Always
	login(nil, "6", nil)
	w.popups.Answer = popup.No
	if _, err := client().Sign(w.key, []byte("data")); err != nil {
		t.Errorf("always didn't cover unbound signatures: %v", err)
	}
	if err := login(other, "7", nil); err == nil {
		t.Error("unbound always covered a server")
	}
	if n := len(w.popups.Asked()); n != 7 {
		t.Errorf("asked %d times", n)
	}
}
