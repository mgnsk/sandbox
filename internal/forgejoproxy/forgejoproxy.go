// Package forgejoproxy is forgejo-api-proxy, the sandbox's Forgejo API
// guard.
//
//	sandbox-bin forgejo-api-proxy PROJECT_TOKENS_FILE
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
//   - GET/HEAD are forwarded as they are;
//   - everything else waits for the user's approval in a popup.
//
// Only hosts there's a token for are forwarded, over HTTPS. Both sources are
// read for each request, so a login on the host (`fj auth add-token`) or a
// `sandbox --fj-token` reaches running sandboxes without a restart.
package forgejoproxy

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/hostname"
	"github.com/mgnsk/sandbox/internal/tokens"
)

// KeysPath is the host fj's keys.json (directories::ProjectDirs' data dir).
func KeysPath() string {
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		home, _ := os.UserHomeDir()
		data = filepath.Join(home, ".local/share")
	}
	return filepath.Join(data, "forgejo-cli", "keys.json")
}

// hostTokens is {host[:port]: token} for every instance logged in to in
// the keys.json at path; empty if it's missing or unreadable. fj keys hosts
// by host[:port][/subpath]; requests only carry host[:port].
func hostTokens(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var keys struct {
		Hosts map[string]jsontext.Value `json:"hosts"`
	}
	if json.Unmarshal(data, &keys) != nil {
		return out
	}
	for name, raw := range keys.Hosts {
		// Logins of every type have a token.
		var login struct {
			Token string `json:"token"`
		}
		host, ok := hostname.Normalize(name)
		if ok && json.Unmarshal(raw, &login) == nil && tokens.Valid(login.Token) {
			out[host] = login.Token
		}
	}
	return out
}

// New is the Forgejo guard: the tokens in tokensFile, else those in the
// host fj's keysFile.
func New(tokensFile, keysFile string) *apiproxy.Proxy {
	lookup := func(host string) (string, bool) {
		all := hostTokens(keysFile)
		maps.Copy(all, tokens.ReadHosts(tokensFile))
		token, ok := all[host]
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
				return apiproxy.Route{}, fmt.Errorf("no token for %[1]s - on the host, outside the sandbox, run"+
					" `sandbox --fj-token %[1]s` in the project (a token for this project)"+
					" or `fj --host %[1]s auth add-token` (the host's, for every project)", host)
			}
			return apiproxy.Route{Host: host, Header: http.Header{"Authorization": {"token " + token}}}, nil
		},
	}}
}

// Run serves on the launcher's listener until stopped.
func Run(ctx context.Context, tokensFile string) error {
	proxy, err := apiproxy.NewHTTPS(New(tokensFile, KeysPath()))
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
