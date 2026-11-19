// Package forgejoproxy is forgejo-api-proxy, the sandbox's Forgejo API
// guard.
//
//	sandbox-bin forgejo-api-proxy PROJECT_TOKENS_FILE
//
// It runs outside the sandbox as an intercepting HTTPS_PROXY on the host's
// loopback, which the launcher maps into the sandbox. Any fj inside sends
// its API requests to instances this proxy has a token for through it, via
// the router (internal/router), without a token - it isn't logged in
// inside. This proxy adds the project's own token for that host (`sandbox
// --fj-token HOST`, from PROJECT_TOKENS_FILE), which never enters the
// sandbox; the host's fj, and any login it has, is never used. Per request
// (the mechanics are apiproxy's):
//
//   - GET/HEAD are forwarded as they are;
//   - everything else waits for the user's approval in a popup.
//
// Only hosts there's a token for are forwarded, over HTTPS. The tokens are
// read for each request, so a `sandbox --fj-token` reaches running
// sandboxes without a restart.
package forgejoproxy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/tokens"
)

// New is the Forgejo guard: the tokens in tokensFile.
func New(tokensFile string) *apiproxy.Proxy {
	lookup := func(host string) (string, bool) {
		token, ok := tokens.ReadHosts(tokensFile)[host]
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
				return apiproxy.Route{}, fmt.Errorf("no token for %[1]s in this project - on the host,"+
					" outside the sandbox, run `sandbox --fj-token %[1]s` in the project", host)
			}
			return apiproxy.Route{Host: host, Header: http.Header{"Authorization": {"token " + token}}}, nil
		},
	}}
}

// Run serves on the launcher's listener until stopped.
func Run(ctx context.Context, tokensFile string) error {
	proxy, err := apiproxy.NewHTTPS(New(tokensFile))
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
