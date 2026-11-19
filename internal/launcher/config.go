package launcher

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// config is the CONFIG.json nix writes for the launcher (see nix/module.nix).
type config struct {
	StateDir          *string        `json:"stateDir"`
	Released          *float64       `json:"released"`
	UpgradeNoticeDays *float64       `json:"upgradeNoticeDays"`
	UserConfig        *userConfigRef `json:"userConfig"`
	HostPorts         []string       `json:"hostPorts"`
	PassEnv           []string       `json:"passEnv"`
	HostEtc           []string       `json:"hostEtc"`
	Guards            struct {
		SSHAgent struct {
			Enable bool    `json:"enable"`
			Socket *string `json:"socket"`
			Path   string  `json:"path"`
		} `json:"sshAgent"`
		SecretService bool `json:"secretService"`
		GitHub        bool `json:"github"`
		Forgejo       bool `json:"forgejo"`
		OpenURL       bool `json:"openUrl"`
	} `json:"guards"`
	Default    profile   `json:"default"`
	Profiles   []profile `json:"profiles"`
	Seccomp    string    `json:"seccomp"`
	ResolvConf *string   `json:"resolvConf"`
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
	HostPath   string `json:"hostPath"`
	DBusDaemon string `json:"dbusDaemon"`
	Project    struct {
		Eval    string `json:"eval"`
		Nixpkgs string `json:"nixpkgs"`
		System  string `json:"system"`
	} `json:"project"`
}

type userConfigRef struct {
	Eval    string `json:"eval"`
	Nixpkgs string `json:"nixpkgs"`
	System  string `json:"system"`
}

type profile struct {
	Name         *string    `json:"name"`
	Env          orderedEnv `json:"env"`
	Binds        []bind     `json:"binds"`
	ClaudeDir    *string    `json:"claudeDir"`
	ClaudeAPIKey bool       `json:"claudeApiKey"`
	Paths        []string   `json:"paths"`
	ProjectFiles []string   `json:"projectFiles"`
	Priority     float64    `json:"priority"`
}

type bind struct {
	Src      string  `json:"src"`
	Dst      *string `json:"dst"`
	Mode     string  `json:"mode"`
	Optional bool    `json:"optional"`
	HideGit  bool    `json:"hideGit"`
}

// envVar is one variable of an environment, which keeps its order.
type envVar struct{ name, value string }

type orderedEnv []envVar

func (e *orderedEnv) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		*e = nil
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("env: not an object")
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		var value string
		if err := dec.Decode(&value); err != nil {
			return err
		}
		*e = append(*e, envVar{key.(string), value})
	}
	_, err = dec.Token()
	return err
}

// set sets name in the environment, in its place if it's there already.
func (e *orderedEnv) set(name, value string) {
	for i := range *e {
		if (*e)[i].name == name {
			(*e)[i].value = value
			return
		}
	}
	*e = append(*e, envVar{name, value})
}

func (e orderedEnv) get(name string) string {
	for _, v := range e {
		if v.name == name {
			return v.value
		}
	}
	return ""
}
