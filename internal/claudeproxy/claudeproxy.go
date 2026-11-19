// Package claudeproxy is claude-api-proxy: Claude Code inside the sandbox
// on an API key that never enters it.
//
//	claude-api-proxy SOCKET KEY_FILE
//
// It runs outside the sandbox, listening on a private socket that the
// launcher binds in. Claude Code inside has ANTHROPIC_UNIX_SOCKET pointing
// here and ANTHROPIC_BASE_URL=http://api.anthropic.com, so it sends its API
// requests here as plain HTTP, with a placeholder key from the managed
// apiKeyHelper. This proxy (the mechanics are apiproxy's):
//
//   - forwards only the paths Claude Code needs (paths, pathPrefixes), to
//     api.anthropic.com over HTTPS - nothing else the key could do, like
//     the Files or Batches APIs;
//   - drops the client's Authorization and x-api-key and adds the project's
//     real key as x-api-key;
//   - asks nothing: Claude Code makes a request per turn, too many for
//     popups.
//
// The key is read from KEY_FILE for each request, so `sandbox
// --claude-api-key` reaches running sandboxes.
//
// Only API keys go through here, never a Claude subscription login:
// Anthropic doesn't allow tools to store or intermediate claude.ai
// credentials.
package claudeproxy

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/cover"
)

const apiHost = "api.anthropic.com"

// Host headers Claude Code sends over the socket: the base URL's for the
// API, "localhost" for a few of its own requests.
var hosts = []string{apiHost, "localhost"}

var (
	paths        = []string{"/v1/messages", "/v1/messages/count_tokens"}
	pathPrefixes = []string{"/v1/models", "/api/claude_code/"}
	keyRE        = regexp.MustCompile(`^[A-Za-z0-9_-]{20,512}$`)
)

// pathAllowed says whether Claude Code needs path (query included).
func pathAllowed(target string) bool {
	path := apiproxy.URLPath(target)
	if slices.Contains(strings.Split(path, "/"), "..") {
		return false
	}
	if slices.Contains(paths, path) {
		return true
	}
	for _, prefix := range pathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// readKey is the key in the file at path, or "" if it's missing or
// malformed.
func readKey(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	key := strings.TrimSpace(string(data))
	if !keyRE.MatchString(key) {
		return ""
	}
	return key
}

type policy struct {
	apiproxy.Defaults
	keyFile string
}

func (policy) Name() string { return "claude-api-proxy" }

func (p policy) HostAllowed(host string) bool {
	return slices.Contains(hosts, host) && readKey(p.keyFile) != ""
}

func (p policy) HostRefusal(host string) string {
	if slices.Contains(hosts, host) {
		return "no Claude API key for this project - run `sandbox --claude-api-key` on the host"
	}
	return p.Defaults.HostRefusal(host)
}

func (policy) PathAllowed(_, path string) bool { return pathAllowed(path) }
func (policy) UpstreamHost(string) string      { return apiHost }
func (policy) CredentialHeaders() []string     { return []string{"x-api-key"} }

func (policy) DescribeWrite(string, string, string, []byte) (string, bool) {
	return "", false
}

func (p policy) Credentials(string) []apiproxy.Header {
	if key := readKey(p.keyFile); key != "" {
		return []apiproxy.Header{{Name: "x-api-key", Value: key}}
	}
	return nil
}

// Main serves on argv[1] with the key in the file argv[2] until killed.
func Main(argv []string) int {
	if len(argv) != 3 {
		fmt.Fprintln(os.Stderr, "usage: claude-api-proxy SOCKET KEY_FILE")
		return 2
	}
	cover.ExitOnTerm()
	err := apiproxy.ServeUnix(argv[1], policy{keyFile: argv[2]})
	fmt.Fprintf(os.Stderr, "claude-api-proxy: %v\n", err)
	return 1
}
