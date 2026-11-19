package launcher

import (
	"encoding/json/v2"
	"fmt"
	"os"
)

// config is the CONFIG.json nix writes for the launcher (see nix/module.nix).
type config struct {
	StateDir          string         `json:"stateDir"`
	Released          int64          `json:"released"` // Unix time of the flake's commit; 0 for builds of your own.
	UpgradeNoticeDays int            `json:"upgradeNoticeDays"`
	UserConfig        *nixEvaluation `json:"userConfig"`
	HostPorts         []string       `json:"hostPorts"`
	PassEnv           []string       `json:"passEnv"`
	HostEtc           []string       `json:"hostEtc"`
	Guards            struct {
		SSHAgent struct {
			Enable bool   `json:"enable"`
			Socket string `json:"socket"`
			Path   string `json:"path"`
		} `json:"sshAgent"`
		SecretService bool `json:"secretService"`
		GitHub        bool `json:"github"`
		Forgejo       bool `json:"forgejo"`
		OpenURL       bool `json:"openUrl"`
	} `json:"guards"`
	Default    profile   `json:"default"`
	Profiles   []profile `json:"profiles"`
	Seccomp    string    `json:"seccomp"`
	ResolvConf string    `json:"resolvConf"`
	FHS        struct {
		Bin    string `json:"bin"`
		UsrBin string `json:"usrBin"`
		NixLd  string `json:"nixLd"`
		LdPath string `json:"ldPath"`
		SSL    string `json:"ssl"`
	} `json:"fhs"`
	Tools struct {
		Pasta string `json:"pasta"`
		IP    string `json:"ip"`
		Bash  string `json:"bash"`
		Bwrap string `json:"bwrap"`
		Shell string `json:"shell"`
	} `json:"tools"`
	Init struct {
		NixProfile  bool `json:"nixProfile"`
		HomeManager bool `json:"homeManager"`
	} `json:"init"`
	HostPath   string        `json:"hostPath"`
	DBusDaemon string        `json:"dbusDaemon"`
	Project    nixEvaluation `json:"project"`
}

// nixEvaluation is a nix file to evaluate a config file with, against a
// nixpkgs.
type nixEvaluation struct {
	Eval    string `json:"eval"`
	Nixpkgs string `json:"nixpkgs"`
	System  string `json:"system"`
}

type profile struct {
	Name         string            `json:"name"`
	Env          map[string]string `json:"env"`
	Binds        []bind            `json:"binds"`
	ClaudeDir    string            `json:"claudeDir"`
	ClaudeAPIKey bool              `json:"claudeApiKey"`
	Paths        []string          `json:"paths"`
	ProjectFiles []string          `json:"projectFiles"`
	Priority     int               `json:"priority"`
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
