package launcher

// Options are the launcher's own, from sandbox-bin launch's flags.
type Options struct {
	// Evaluate sandbox.nix and the user config again, even if unchanged.
	Reload bool
	// Ignore sandbox.nix.
	NoProjectConfig bool
	// Set this project's Claude API key, and exit.
	ClaudeAPIKey bool
}
