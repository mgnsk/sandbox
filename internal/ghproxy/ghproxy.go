// Package ghproxy is gh-api-proxy, the sandbox's GitHub API guard.
//
//	gh-api-proxy PROJECT_TOKEN_FILE
//
// It runs outside the sandbox as an intercepting HTTPS_PROXY on the host's
// loopback, which the launcher maps into the sandbox. The sandbox's gh
// (upstream gh, wrapped to set HTTPS_PROXY and trust this proxy's CA) sends
// every API request through it, with only a placeholder token. This proxy
// holds the real token, which never enters the sandbox: the project's own
// (`sandbox --gh-token`, from PROJECT_TOKEN_FILE, read per request) if it
// has one, else the host gh's. It decides per request (the mechanics are
// apiproxy's):
//
//   - REST GET/HEAD, and GraphQL documents containing only queries, are
//     forwarded as they are;
//   - everything else - REST writes, GraphQL mutations/subscriptions, and
//     anything it can't parse - waits for the user's approval in a popup.
//
// Only tokenHosts are intercepted; the client's Authorization header is
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
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/tokens"
)

const apiHost = "api.github.com"

// Hosts that get the real token: intercepted, each request read.
var tokenHosts = []string{apiHost, "uploads.github.com"}

// Hosts gh is redirected to for downloads (release assets, archives, run
// logs/artifacts), and github.com for git under gh (which inherits
// HTTPS_PROXY). Tunneled as they are, without a token - the sandbox could
// reach them directly anyway; the list just keeps this from being an open
// proxy (which would also reach the host's own services).
var (
	tunnelHosts        = []string{"github.com", "codeload.github.com"}
	tunnelHostSuffixes = []string{".githubusercontent.com", ".blob.core.windows.net"}
)

var errNoToken = errors.New("no GitHub token - on the host, outside the sandbox, run `sandbox --gh-token`" +
	" in the project (a token for this project) or `gh auth login` (the host's," +
	" for every project; restart the sandbox after it)")

// tunnel says whether a CONNECT to hostport passes through unread.
func tunnel(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port != "443" || slices.Contains(tokenHosts, host) {
		return false
	}
	return slices.Contains(tunnelHosts, host) || slices.ContainsFunc(tunnelHostSuffixes, func(suffix string) bool {
		return strings.HasSuffix(host, suffix)
	})
}

// New is the GitHub guard: the token in tokenFile, else hostToken.
func New(tokenFile, hostToken string) *apiproxy.Proxy {
	token := func() string {
		if token := tokens.Read(tokenFile); token != "" {
			return token
		}
		return hostToken
	}
	return &apiproxy.Proxy{Guard: apiproxy.Guard{
		Name:  "gh-api-proxy",
		Title: "Allow sandboxed GitHub API write?",
		Route: func(host string) (apiproxy.Route, error) {
			if !slices.Contains(tokenHosts, host) {
				return apiproxy.Route{}, fmt.Errorf("host not allowed: %s", host)
			}
			token := token()
			if token == "" {
				return apiproxy.Route{}, errNoToken
			}
			return apiproxy.Route{Host: host, Header: http.Header{"Authorization": {"token " + token}}}, nil
		},
		Describe: describe,
		Tunnel:   tunnel,
	}}
}

// hostToken is the host gh's token, for the proxy's lifetime only; "" if gh
// isn't logged in (or there's no gh).
func hostToken() string {
	out, err := exec.Command("gh", "auth", "token").Output()
	if token := strings.TrimSpace(string(out)); err == nil && tokens.Valid(token) {
		return token
	}
	return ""
}

// Main serves on the launcher's listener until stopped.
func Main(argv []string) int {
	return guard.Main(argv, "gh-api-proxy PROJECT_TOKEN_FILE", 1, func(ctx context.Context, args []string) error {
		hostToken := hostToken()
		if tokens.Read(args[0]) == "" && hostToken == "" {
			fmt.Fprintf(os.Stderr, "sandbox: %v\n", errNoToken)
		}
		proxy, err := apiproxy.NewHTTPS(New(args[0], hostToken))
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
	})
}
