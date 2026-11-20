// Package claudeproxy is claude-api-proxy: Claude Code inside the sandbox
// on an API key that never enters it.
//
//	sandbox-bin claude-api-proxy   (the key on guard.SecretFD)
//
// It runs outside the sandbox, on a private socket that the launcher binds
// in. Claude Code inside has ANTHROPIC_UNIX_SOCKET pointing here and
// ANTHROPIC_BASE_URL=http://api.anthropic.com, so it sends its API requests
// here as plain HTTP, with a placeholder key from the managed apiKeyHelper.
// This proxy (the mechanics are apiproxy's):
//
//   - forwards only the paths Claude Code needs (paths, pathPrefixes), to
//     api.anthropic.com over HTTPS - nothing else the key could do, like
//     the Files or Batches APIs;
//   - drops the client's Authorization and x-api-key and adds the project's
//     real key as x-api-key;
//   - asks nothing: Claude Code makes a request per turn, too many for
//     popups.
//
// The key is the one its token command printed at start
// (guards.claudeApiKey.tokenCommand, from the user's config or an approved
// sandbox.nix), piped in by the launcher and kept in memory only.
//
// Only API keys go through here, never a Claude subscription login:
// Anthropic doesn't allow tools to store or intermediate claude.ai
// credentials.
package claudeproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/mgnsk/sandbox/internal/apiproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/tokens"
)

const apiHost = "api.anthropic.com"

// Host headers Claude Code sends over the socket: the base URL's for the
// API, "localhost" for a few of its own requests.
var hosts = []string{apiHost, "localhost"}

var (
	paths        = []string{"/v1/messages", "/v1/messages/count_tokens"}
	pathPrefixes = []string{"/v1/models", "/api/claude_code/"}
)

var errNoKey = errors.New("no Claude API key - the launcher passed none")

// allowPath says whether Claude Code needs p. Only a path that reads the
// same to any server: clean, and without the characters some take for a
// separator or a parameter.
func allowPath(p string) bool {
	if path.Clean(p) != p || strings.ContainsAny(p, `;\`) {
		return false
	}
	return slices.Contains(paths, p) || slices.ContainsFunc(pathPrefixes, func(prefix string) bool {
		return strings.HasPrefix(p, prefix)
	})
}

// New is the Claude API guard with key; "" refuses every request.
func New(key string) *apiproxy.Proxy {
	return &apiproxy.Proxy{Guard: apiproxy.Guard{
		Name: "claude-api-proxy",
		Route: func(host string) (apiproxy.Route, error) {
			if !slices.Contains(hosts, host) {
				return apiproxy.Route{}, fmt.Errorf("host not allowed: %s", host)
			}
			if key == "" {
				return apiproxy.Route{}, errNoKey
			}
			return apiproxy.Route{Host: apiHost, Header: http.Header{"X-Api-Key": {key}}}, nil
		},
		AllowPath:   allowPath,
		Describe:    func(*http.Request, string) (string, error) { return "", nil },
		DropHeaders: []string{"X-Api-Key"},
	}}
}

// Run serves on the launcher's listener until stopped, with the key the
// launcher piped in.
func Run(ctx context.Context) error {
	secret, err := guard.Secret()
	if err != nil {
		return err
	}
	key := strings.TrimSpace(string(secret))
	if !tokens.Valid(key) {
		return errors.New("the launcher's key isn't one")
	}
	p := New(key)
	ln, err := guard.Listener()
	if err != nil {
		return err
	}
	if err := guard.Ready(struct{}{}); err != nil {
		return err
	}
	return p.Serve(ctx, ln)
}
