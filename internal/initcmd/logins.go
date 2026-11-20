package initcmd

import (
	"encoding/json/v2"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// A login stored inside is readable by all sandboxed code and used around
// the API guards and their popups; tokens belong in token commands.
const loginRisk = "a token stored inside is readable by everything in the sandbox and bypasses the host proxy's write popups"

// envDir is $name, or home/fallback when it's unset or relative (as the XDG
// spec says to treat it).
func envDir(name, home, fallback string) string {
	if dir := os.Getenv(name); filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(home, fallback)
}

// ghLogins lists the hosts gh is logged in to inside: the keys of its
// hosts.yml, whether the token is in the file or the (fake) keyring.
func ghLogins(home string) (string, []string) {
	dir := os.Getenv("GH_CONFIG_DIR")
	if dir == "" {
		dir = filepath.Join(envDir("XDG_CONFIG_HOME", home, ".config"), "gh")
	}
	path := filepath.Join(dir, "hosts.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return path, nil
	}
	var hosts map[string]any
	if yaml.Unmarshal(data, &hosts) != nil {
		return path, nil
	}
	return path, slices.Sorted(maps.Keys(hosts))
}

// fjLogins lists the hosts fj is logged in to inside, from its keys.json.
func fjLogins(home string) (string, []string) {
	path := filepath.Join(envDir("XDG_DATA_HOME", home, ".local/share"), "forgejo-cli", "keys.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return path, nil
	}
	var keys struct {
		Hosts map[string]any `json:"hosts"`
	}
	if json.Unmarshal(data, &keys) != nil {
		return path, nil
	}
	return path, slices.Sorted(maps.Keys(keys.Hosts))
}

// warnStoredLogins warns of gh and fj logins made inside the sandbox, which
// the launcher can't prevent: gh auth login with GH_TOKEN cleared, fj auth
// add-token with a pasted token, or either before this check existed.
func warnStoredLogins(home string) {
	if path, hosts := ghLogins(home); len(hosts) > 0 {
		var logout []string
		for _, h := range hosts {
			logout = append(logout, "gh auth logout --hostname "+h)
		}
		warn("WARNING: gh is logged in inside the sandbox (%s: %s) - %s.\n"+
			"  Run `%s` here, revoke that token, and use guards.github.tokenCommand instead.",
			path, strings.Join(hosts, ", "), loginRisk, strings.Join(logout, "; "))
	}
	if path, hosts := fjLogins(home); len(hosts) > 0 {
		var logout []string
		for _, h := range hosts {
			logout = append(logout, "fj auth logout "+h)
		}
		warn("WARNING: fj is logged in inside the sandbox (%s: %s) - %s.\n"+
			"  Run `%s` here, revoke that token, and use guards.forgejo.tokenCommands instead.",
			path, strings.Join(hosts, ", "), loginRisk, strings.Join(logout, "; "))
	}
}
