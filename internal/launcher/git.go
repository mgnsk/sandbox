package launcher

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// gitSettings are git's identity and signing inside: the flake's
// (git.fromHost and the signing key, for everyone on the project), a user's
// .sandbox.yml's over them, and what the host's own git config fills in.
// They only set git's environment inside; a signing key command runs on
// the host, once approved like the token commands.
type gitSettings struct {
	UserName, UserEmail string
	// An ssh public key, signing through the agent.
	SigningKey string
	// Prints SigningKey on the host at start.
	SigningKeyCommand string
	// Fill what isn't set from the host's global git config (see hostGit);
	// nil doesn't say.
	FromHost *bool
}

// over is g with base's signing key, or command, when g has neither - one
// of its own replaces both - and base's word on the host's identity when g
// has none.
func (g gitSettings) over(base gitSettings) gitSettings {
	if g.SigningKey == "" && g.SigningKeyCommand == "" {
		g.SigningKey, g.SigningKeyCommand = base.SigningKey, base.SigningKeyCommand
	}
	if g.FromHost == nil {
		g.FromHost = base.FromHost
	}
	return g
}

func (g gitSettings) fromHost() bool { return g.FromHost != nil && *g.FromHost }

// withHost is g with what it doesn't set from h: explicit settings win, and
// a signing key or command of its own keeps the host's key out.
func (g gitSettings) withHost(h hostGit) gitSettings {
	if g.UserName == "" {
		g.UserName = h.Name
	}
	if g.UserEmail == "" {
		g.UserEmail = h.Email
	}
	if g.SigningKey == "" && g.SigningKeyCommand == "" {
		g.SigningKey = h.SigningKey
	}
	return g
}

// check says what's wrong with g as a project's file has it.
func (g gitSettings) check() error {
	switch {
	case g.SigningKey != "" && !isSSHPublicKey(g.SigningKey):
		return fmt.Errorf("git.signingKey must be an ssh public key (ssh-ed25519 AAAA...)")
	case g.SigningKey != "" && g.SigningKeyCommand != "":
		return fmt.Errorf("git.signingKey and git.signingKeyCommand: set one")
	}
	return checkCommand(g.SigningKeyCommand)
}

func isSSHPublicKey(key string) bool {
	kind, data, ok := strings.Cut(key, " ")
	return ok && data != "" && !strings.Contains(key, "\n") &&
		(strings.HasPrefix(kind, "ssh-") || strings.HasPrefix(kind, "ecdsa-") || strings.HasPrefix(kind, "sk-"))
}

// resolveSigningKey runs the (approved) signing key command, if any, for
// SigningKey: its output must be an ssh public key.
func (g *gitSettings) resolveSigningKey(ctx context.Context, l *launcher) error {
	if g.SigningKeyCommand == "" {
		return nil
	}
	key, err := l.runHostCommand(ctx, "git.signingKeyCommand", g.SigningKeyCommand)
	if err != nil {
		return err
	}
	if !isSSHPublicKey(key) {
		return fmt.Errorf("git.signingKeyCommand (%s) didn't print an ssh public key", g.SigningKeyCommand)
	}
	g.SigningKey = key
	return nil
}

// setEnv sets g in the environment inside: author and committer, and ssh
// signing of commits and tags with the agent's key, as git config entries
// after any the profile's env has.
func (g gitSettings) setEnv(inside map[string]string) {
	if g.UserName != "" {
		inside["GIT_AUTHOR_NAME"] = g.UserName
		inside["GIT_COMMITTER_NAME"] = g.UserName
	}
	if g.UserEmail != "" {
		inside["GIT_AUTHOR_EMAIL"] = g.UserEmail
		inside["GIT_COMMITTER_EMAIL"] = g.UserEmail
	}
	if g.SigningKey == "" {
		return
	}
	count, _ := strconv.Atoi(inside["GIT_CONFIG_COUNT"])
	for _, kv := range [][2]string{
		{"user.signingKey", g.SigningKey},
		{"gpg.format", "ssh"},
		{"commit.gpgSign", "true"},
		{"tag.gpgSign", "true"},
	} {
		inside[fmt.Sprintf("GIT_CONFIG_KEY_%d", count)] = kv[0]
		inside[fmt.Sprintf("GIT_CONFIG_VALUE_%d", count)] = kv[1]
		count++
	}
	inside["GIT_CONFIG_COUNT"] = strconv.Itoa(count)
}

// gitEnv sets git's identity and signing in the environment inside, from
// the project's settings and, where they ask for it, the host's. The keys
// git inside signs with are the ssh agent guard's to know: the settings',
// and the host's own either way, as git inside may be on the user's git
// config, which home-manager links in.
func (l *launcher) gitEnv(ctx context.Context, git gitSettings, inside map[string]string) error {
	var host hostGit
	if !l.opts.Eval && (git.fromHost() || l.cfg.Guards.SSHAgent.Enable) {
		host = readHostGit(ctx, l.home)
	}
	if git.fromHost() {
		git = git.withHost(host)
	}
	if err := git.resolveSigningKey(ctx, l); err != nil {
		return err
	}
	git.setEnv(inside)
	l.signingKeys = []string{git.SigningKey, host.SigningKey}
	return nil
}
