package router

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
)

// The launcher's variables naming the guards' proxies (secret included) and
// the CA bundle that trusts them; see internal/launcher/guards.go.
const (
	GitHubEnv  = "SANDBOX_GH_PROXY"
	ForgejoEnv = "SANDBOX_FJ_PROXY"
	CAFileEnv  = "SANDBOX_CA_FILE"
	secretEnv  = "SANDBOX_ROUTER_SECRET"
)

// Start starts the router as a child of this process (sandbox-bin init) when
// environ names a guard, and returns the environment for the command init
// execs: HTTPS_PROXY pointing at the router, the guards' CAs trusted, and
// the guards' own URLs left out. Without a guard, environ as it is.
//
// The router gets its listener already bound, so it's ready before the
// command starts, and a session of its own, so a Ctrl-C to the command's
// process group doesn't reach it. It lives until the sandbox's pid
// namespace ends.
func Start(environ []string) ([]string, error) {
	env := envMap(environ)
	if env[GitHubEnv] == "" && env[ForgejoEnv] == "" {
		return environ, nil
	}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	file, err := ln.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	secret := rand.Text()
	cmd := exec.Command("/proc/self/exe", "router")
	cmd.Env = []string{
		secretEnv + "=" + secret,
		GitHubEnv + "=" + env[GitHubEnv],
		ForgejoEnv + "=" + env[ForgejoEnv],
	}
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the router: %w", err)
	}

	return commandEnv(environ, fmt.Sprintf("http://sandbox:%s@%s", secret, ln.Addr())), nil
}

// commandEnv is environ with HTTPS_PROXY set to proxy, the guards' CAs
// trusted and the guards' own URLs left out.
func commandEnv(environ []string, proxy string) []string {
	env := envMap(environ)
	set := map[string]string{
		"HTTPS_PROXY": proxy,
		"https_proxy": proxy,
		"NO_PROXY":    noProxy(env["NO_PROXY"]),
		"no_proxy":    noProxy(env["no_proxy"]),
	}
	if ca := env[CAFileEnv]; ca != "" {
		// Every TLS client that might meet a guard: Go and OpenSSL (gh, curl,
		// git, Python's ssl), nix's fetchers and nixpkgs' certifi, Node
		// (Claude Code, npm scripts), and requests with a pip-installed
		// certifi.
		for _, name := range []string{"SSL_CERT_FILE", "NIX_SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
			set[name] = ca
		}
	}
	out := make([]string, 0, len(environ)+len(set))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if _, replaced := set[name]; replaced || name == GitHubEnv || name == ForgejoEnv {
			continue
		}
		out = append(out, kv)
	}
	for _, name := range slices.Sorted(maps.Keys(set)) {
		out = append(out, name+"="+set[name])
	}
	return out
}

// noProxy is existing plus the loopback names, so dev servers inside are
// reached directly.
func noProxy(existing string) string {
	local := "localhost,127.0.0.1,::1"
	if existing == "" {
		return local
	}
	return existing + "," + local
}

func envMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		env[name] = value
	}
	return env
}

// Main is sandbox-bin router: serves on the listener Start passed as fd 3.
func Main() error {
	r := &Router{Secret: os.Getenv(secretEnv)}
	if r.Secret == "" {
		return errors.New("no " + secretEnv + " (sandbox-bin init starts the router)")
	}
	for name, dst := range map[string]**url.URL{GitHubEnv: &r.GitHub, ForgejoEnv: &r.Forgejo} {
		if value := os.Getenv(name); value != "" {
			u, err := url.Parse(value)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			*dst = u
		}
	}
	ln, err := net.FileListener(os.NewFile(3, "listener"))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	return r.Serve(ctx, ln)
}
