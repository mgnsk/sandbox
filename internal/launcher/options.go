package launcher

// Options are the launcher's own, from sandbox-bin launch's flags.
type Options struct {
	// Evaluate sandbox.nix again, even if unchanged.
	Reload bool
	// Ignore sandbox.nix and .sandbox.yml.
	NoProjectConfig bool
	// The sandbox sandbox.nix is evaluated in: without the project's
	// config, and without guards, token commands or host ports. What runs
	// in it is the project's.
	Eval bool
}
