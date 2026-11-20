// Package forgejoproxy is forgejo-api-proxy, the sandbox's Forgejo API
// guard.
//
//	sandbox-bin forgejo-api-proxy   (a JSON {host: token} on guard.SecretFD)
//
// It runs outside the sandbox as an intercepting HTTPS_PROXY on the host's
// loopback, which the launcher maps into the sandbox. Any fj inside sends
// its API requests to instances this proxy has a token for through it, via
// the router (internal/router), without a token - it isn't logged in
// inside. This proxy adds the token for that host, which never enters the
// sandbox: the one its token command printed at start
// (guards.forgejo.tokenCommands, from the user's config or an approved
// sandbox.nix), piped in by the launcher and kept in memory only. The host's fj, and any login it
// has, is never used. Per request (the mechanics are apiproxy's):
//
//   - OAuth endpoints (/login/oauth/...) are refused, so `fj auth login`
//     can't get a token inside: one stored there would be readable by all
//     sandboxed code and used around this proxy;
//   - GET/HEAD are forwarded as they are;
//   - everything else waits for the user's approval in a popup.
//
// Only hosts there's a token for are forwarded, over HTTPS.
package forgejoproxy

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/tokens"
)

// New is the Forgejo guard with hostTokens, {host[:port]: token}.
func New(hostTokens map[string]string) *apiproxy.Proxy {
	lookup := func(host string) (string, bool) {
		token, ok := hostTokens[host]
		return token, ok
	}
	return &apiproxy.Proxy{Guard: apiproxy.Guard{
		Name:  "forgejo-api-proxy",
		Title: "Allow sandboxed Forgejo API write?",
		// Every proxy-aware client inside goes through the router, which
		// asks here first: only hosts with a token are this guard's.
		Handles: func(host string) bool {
			_, ok := lookup(host)
			return ok
		},
		Route: func(host string) (apiproxy.Route, error) {
			token, ok := lookup(host)
			if !ok {
				return apiproxy.Route{}, fmt.Errorf("no token for %s - add a command printing one to"+
					" guards.forgejo.tokenCommands, in sandbox.nix or your sandbox config", host)
			}
			return apiproxy.Route{Host: host, Header: http.Header{"Authorization": {"token " + token}}}, nil
		},
		AllowPath: allowPath,
	}}
}

// allowPath refuses Forgejo's OAuth endpoints, where `fj auth login` trades
// its authorization code for a token. Cleaned and lowercased first, so
// `//login/./OAuth/...` doesn't slip past.
func allowPath(p string) bool {
	p = strings.ToLower(path.Clean("/" + p))
	return p != "/login/oauth" && !strings.HasPrefix(p, "/login/oauth/")
}

// Run serves on the launcher's listener until stopped.
func Run(ctx context.Context) error {
	secret, err := guard.Secret()
	if err != nil {
		return err
	}
	hostTokens := map[string]string{}
	if len(secret) > 0 {
		if err := json.Unmarshal(secret, &hostTokens); err != nil {
			return fmt.Errorf("the launcher's tokens: %w", err)
		}
	}
	for host, token := range hostTokens {
		if !tokens.Valid(token) {
			return fmt.Errorf("the launcher's token for %s isn't one", host)
		}
	}
	proxy, err := apiproxy.NewHTTPS(New(hostTokens))
	if err != nil {
		return err
	}
	ln, err := guard.Listener()
	if err != nil {
		return err
	}
	if err := guard.Ready(proxy.Info()); err != nil {
		return err
	}
	return proxy.Serve(ctx, ln)
}
