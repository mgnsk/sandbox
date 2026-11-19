// Package forgejoproxy is forgejo-api-proxy, the sandbox's Forgejo API
// guard.
//
//	forgejo-api-proxy STATE_DIR PROJECT_TOKENS_FILE
//
// It runs outside the sandbox as an intercepting HTTPS_PROXY on the host's
// loopback, which the launcher maps into the sandbox. The sandbox's fj
// (upstream forgejo-cli, wrapped to set HTTPS_PROXY and trust this proxy's
// CA) sends every API request through it, without a token - it isn't logged
// in inside. This proxy adds a token, which never enters the sandbox - the
// project's own for that host (`sandbox --fj-token HOST`, from
// PROJECT_TOKENS_FILE) if it has one, else the host fj's - and per request
// (the mechanics are apiproxy's):
//
//   - GET/HEAD are forwarded as-is;
//   - everything else waits for the user's approval in a popup.
//
// Only hosts there's a token for are forwarded, over HTTPS. Both sources are
// read for each request, so a login on the host (`fj auth add-token`) or a
// `sandbox --fj-token` reaches running sandboxes without a restart.
package forgejoproxy

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/cover"
)

var hostRE = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?$`)

// keysPath is the host fj's keys.json (directories::ProjectDirs' data dir).
func keysPath() string {
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		home, _ := os.UserHomeDir()
		data = filepath.Join(home, ".local/share")
	}
	return filepath.Join(data, "forgejo-cli", "keys.json")
}

// safeToken says whether token can go in a header as it is.
func safeToken(token string) bool {
	for i := 0; i < len(token); i++ {
		if c := token[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return token != ""
}

// hostTokens is {host[:port]: token} for every instance logged in to in
// keys.json at path; empty if it's missing or unreadable. fj keys hosts by
// host[:port][/subpath]; requests only carry host[:port].
func hostTokens(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var keys struct {
		Hosts map[string]json.RawMessage `json:"hosts"`
	}
	if json.Unmarshal(data, &keys) != nil {
		return out
	}
	for name, raw := range keys.Hosts {
		var login map[string]any
		if json.Unmarshal(raw, &login) != nil {
			continue
		}
		if token, ok := login["token"].(string); ok && safeToken(token) {
			host, _, _ := strings.Cut(name, "/")
			out[strings.ToLower(host)] = token
		}
	}
	return out
}

type policy struct {
	apiproxy.Defaults
	projectFile string
}

func (policy) Name() string       { return "forgejo-api-proxy" }
func (policy) PopupTitle() string { return "Allow sandboxed Forgejo API write?" }

// tokens: the host fj's, overridden by the project's.
func (p policy) tokens() map[string]string {
	tokens := hostTokens(keysPath())
	maps.Copy(tokens, apiproxy.ReadTokens(p.projectFile))
	return tokens
}

func (p policy) HostAllowed(host string) bool {
	_, ok := p.tokens()[host]
	return hostRE.MatchString(host) && ok
}

func (policy) HostRefusal(host string) string {
	return fmt.Sprintf("no token for %s - on the host, outside the sandbox, run"+
		" `sandbox --fj-token %s` in the project (a token for this project)"+
		" or `fj --host %s auth add-token` (the host's, for every project)", host, host, host)
}

func (p policy) Credentials(host string) []apiproxy.Header {
	if token := p.tokens()[host]; token != "" {
		return []apiproxy.Header{{Name: "Authorization", Value: "token " + token}}
	}
	return nil
}

// Main serves until killed, announcing the port, secret and CA in argv[1];
// argv[2] is the project's {host: token} file.
func Main(argv []string) int {
	if len(argv) != 3 {
		fmt.Fprintln(os.Stderr, "usage: forgejo-api-proxy STATE_DIR PROJECT_TOKENS_FILE")
		return 2
	}
	cover.ExitOnTerm()
	proxy, err := apiproxy.NewHTTPSProxy(policy{projectFile: argv[2]})
	if err == nil {
		err = proxy.Announce(argv[1])
	}
	if err == nil {
		err = proxy.Serve()
	}
	fmt.Fprintf(os.Stderr, "forgejo-api-proxy: %v\n", err)
	return 1
}
