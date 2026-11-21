// Package ghproxy is gh-api-proxy, the sandbox's GitHub API guard.
//
//	sandbox-bin gh-api-proxy   (the token on guard.SecretFD)
//
// It runs outside the sandbox as an intercepting HTTPS_PROXY on the host's
// loopback, which the launcher maps into the sandbox. Any gh inside sends
// its API requests through it, via the router (internal/router), with only
// a placeholder token. This proxy
// holds the real token, which never enters the sandbox: the one the token
// command printed at start (guards.github.tokenCommand, from the user's
// config or an approved project flake), which the launcher pipes in and this
// keeps in memory only. The host's gh, and any login it has, is never used. It
// decides per request (the mechanics are apiproxy's):
//
//   - REST GET/HEAD, and GraphQL documents containing only queries, are
//     forwarded as they are;
//   - everything else - REST writes, GraphQL mutations/subscriptions, and
//     anything it can't parse - waits for the user's approval in a popup.
//
// Only TokenHosts are intercepted; the client's Authorization header is
// always dropped and the real token added. The download hosts gh is
// redirected to, and the web host for git under gh, are tunneled unread. gh
// and git themselves run inside the sandbox, so nothing here ever executes
// them against the sandbox's files.
package ghproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/tokens"
)

const apiHost = "api.github.com"

// TokenHosts get the real token: intercepted, each request read. The
// sandbox's router sends CONNECTs to them here.
var TokenHosts = []string{apiHost, "uploads.github.com"}

// Hosts gh is redirected to for downloads (release assets, archives, run
// logs/artifacts), and github.com for git under gh (which inherits
// HTTPS_PROXY). Tunneled as they are, without a token - the sandbox could
// reach them directly anyway; the list just keeps this from being an open
// proxy (which would also reach the host's own services).
var (
	tunnelHosts        = []string{"github.com", "codeload.github.com"}
	tunnelHostSuffixes = []string{".githubusercontent.com", ".blob.core.windows.net"}
)

// tunnel says whether a CONNECT to hostport passes through unread.
func tunnel(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port != "443" || slices.Contains(TokenHosts, host) {
		return false
	}
	return slices.Contains(tunnelHosts, host) || slices.ContainsFunc(tunnelHostSuffixes, func(suffix string) bool {
		return strings.HasSuffix(host, suffix)
	})
}

// New is the GitHub guard with token; "" refuses every request.
func New(token string) *apiproxy.Proxy {
	return &apiproxy.Proxy{Guard: apiproxy.Guard{
		Name:  "gh-api-proxy",
		Title: "Allow sandboxed GitHub API write?",
		Route: func(host string) (apiproxy.Route, error) {
			if !slices.Contains(TokenHosts, host) {
				return apiproxy.Route{}, fmt.Errorf("host not allowed: %s", host)
			}
			return apiproxy.TokenRoute(host, token), nil
		},
		Describe: describe,
		Tunnel:   tunnel,
		// Any other host is refused before a certificate is made for it.
		Handles: func(host string) bool { return slices.Contains(TokenHosts, host) },
	}}
}

// Run serves on the launcher's listener until stopped.
func Run(ctx context.Context) error {
	secret, err := guard.Secret()
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(secret))
	if !tokens.Valid(token) {
		return errors.New("the launcher's token isn't one")
	}
	return apiproxy.RunHTTPS(ctx, New(token), TokenHosts...)
}
