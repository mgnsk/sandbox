// Package ghproxy is gh-api-proxy, the sandbox's GitHub API guard.
//
//	gh-api-proxy STATE_DIR PROJECT_TOKEN_FILE
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
//     forwarded as-is;
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
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/cover"
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
	otherHosts        = []string{"github.com", "codeload.github.com"}
	otherHostSuffixes = []string{".githubusercontent.com", ".blob.core.windows.net"}
	hostRE            = regexp.MustCompile(`^[a-z0-9.-]+$`)
)

// GraphQL bodies are read in full to classify them; everything else
// streams.
const maxGraphQLBody = 10 * 1024 * 1024

const noToken = "no GitHub token - on the host, outside the sandbox, run `sandbox --gh-token`" +
	" in the project (a token for this project) or `gh auth login` (the host's," +
	" for every project; restart the sandbox after it)"

func tunnelAllowed(host string) bool {
	if !hostRE.MatchString(host) || slices.Contains(tokenHosts, host) {
		return false
	}
	if slices.Contains(otherHosts, host) {
		return true
	}
	for _, suffix := range otherHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

type policy struct {
	apiproxy.Defaults
	projectFile string
	hostToken   string
}

func (policy) Name() string       { return "gh-api-proxy" }
func (policy) PopupTitle() string { return "Allow sandboxed GitHub API write?" }

// token: the project's, else the host gh's; "" for none.
func (p policy) token() string {
	if token := apiproxy.ReadToken(p.projectFile); token != "" {
		return token
	}
	return p.hostToken
}

func (p policy) HostAllowed(host string) bool {
	return slices.Contains(tokenHosts, host) && p.token() != ""
}

func (p policy) HostRefusal(host string) string {
	if slices.Contains(tokenHosts, host) {
		return noToken
	}
	return p.Defaults.HostRefusal(host)
}

func (policy) TunnelAllowed(host string) bool { return tunnelAllowed(host) }

func (policy) BodyLimit(host, path string) (int64, bool) {
	if host == apiHost && strings.TrimRight(apiproxy.URLPath(path), "/") == "/graphql" {
		return maxGraphQLBody, true
	}
	return 0, false
}

func (policy) DescribeWrite(method, host, path string, body []byte) (string, bool) {
	return describeWrite(method, host, path, body)
}

func (p policy) Credentials(host string) []apiproxy.Header {
	if token := p.token(); token != "" && slices.Contains(tokenHosts, host) {
		return []apiproxy.Header{{Name: "Authorization", Value: "token " + token}}
	}
	return nil
}

// hostToken is the host gh's token, for the proxy's lifetime only; "" if gh
// isn't logged in (or there's no gh).
func hostToken() string {
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	token := strings.TrimSpace(string(out))
	if !apiproxy.ValidToken(token) {
		return ""
	}
	return token
}

// Main serves until killed, announcing the port, secret and CA in argv[1];
// argv[2] is the project's token file.
func Main(argv []string) int {
	if len(argv) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gh-api-proxy STATE_DIR PROJECT_TOKEN_FILE")
		return 2
	}
	p := policy{projectFile: argv[2], hostToken: hostToken()}
	if p.token() == "" {
		fmt.Fprintf(os.Stderr, "sandbox: %s\n", noToken)
	}
	cover.ExitOnTerm()
	proxy, err := apiproxy.NewHTTPSProxy(p)
	if err == nil {
		err = proxy.Announce(argv[1])
	}
	if err == nil {
		err = proxy.Serve()
	}
	fmt.Fprintf(os.Stderr, "gh-api-proxy: %v\n", err)
	return 1
}
