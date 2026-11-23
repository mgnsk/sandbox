package launcher

import (
	"encoding/json/v2"
	"fmt"
	"os"
)

// config is the CONFIG.json nix writes for the launcher (see nix/module.nix).
type config struct {
	StateDir  string   `json:"stateDir"`
	HostPorts []string `json:"hostPorts"`
	// What the sandbox reaches besides the public internet (see
	// parseAllowNet).
	AllowNet []string `json:"allowNet"`
	PassEnv  []string `json:"passEnv"`
	HostEtc  []string `json:"hostEtc"`
	Guards   struct {
		SSHAgent struct {
			Enable bool   `json:"enable"`
			Socket string `json:"socket"`
			Path   string `json:"path"`
		} `json:"sshAgent"`
		SecretService bool `json:"secretService"`
		OpenURL       bool `json:"openUrl"`
		// The guards' popups as desktop notifications too, in a sandbox
		// with a Wayland display.
		Notifications bool `json:"notifications"`
		Wayland       struct {
			Enable bool `json:"enable"`
			// The user's changes to the allowlist, over the defaults and
			// the project's.
			Globals        map[string]bool `json:"globals"`
			DefaultGlobals []string        `json:"defaultGlobals"`
		} `json:"wayland"`
	} `json:"guards"`
	Default    profile   `json:"default"`
	Profiles   []profile `json:"profiles"`
	Seccomp    string    `json:"seccomp"`
	ResolvConf string    `json:"resolvConf"`
	FHS        struct {
		Bin    string `json:"bin"`
		UsrBin string `json:"usrBin"`
		// bash-completion's share dir, bound at /usr/share/bash-completion,
		// and the managed /etc/bashrc and /etc/profile.
		BashCompletion string `json:"bashCompletion"`
		Bashrc         string `json:"bashrc"`
		Profile        string `json:"profile"`
		NixLd          string `json:"nixLd"`
		LdPath         string `json:"ldPath"`
		SSL            string `json:"ssl"`
	} `json:"fhs"`
	Tools struct {
		Pasta string `json:"pasta"`
		IP    string `json:"ip"`
		Nft   string `json:"nft"`
		Bash  string `json:"bash"`
		Bwrap string `json:"bwrap"`
		Shell string `json:"shell"`
		// The Wayland guard's proxy.
		WlVeil string `json:"wlVeil"`
	} `json:"tools"`
	Init struct {
		NixProfile  bool `json:"nixProfile"`
		HomeManager bool `json:"homeManager"`
	} `json:"init"`
	HostPath   string `json:"hostPath"`
	DBusDaemon string `json:"dbusDaemon"`
	// Files at /etc/<path> inside, read-only: Claude Code's managed
	// config, AGENTS.md, ...
	Etc []etcFile `json:"etc"`
	Git struct {
		FromHost bool `json:"fromHost"`
	} `json:"git"`
}

type etcFile struct {
	Path   string `json:"path"`
	Source string `json:"source"`
}

type profile struct {
	// For a reader of the config; nothing goes by it.
	Name  string            `json:"name"`
	Env   map[string]string `json:"env"`
	Binds []bind            `json:"binds"`
	tokenCommands
	Paths    []string `json:"paths"`
	Priority int      `json:"priority"`
}

type bind struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"` // Src's own path when empty.
	Mode     string `json:"mode"`
	Optional bool   `json:"optional"`
	HideGit  bool   `json:"hideGit"`
}

func readConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}
