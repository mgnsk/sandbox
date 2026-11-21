package launcher

// Options are the launcher's own, from sandbox-bin launch's flags.
type Options struct {
	// Evaluate flake.nix's sandbox config again, even if unchanged.
	Reload bool
	// Ignore flake.nix's sandbox config and .sandbox.yml.
	NoProjectConfig bool
	// The sandbox flake.nix is evaluated in: without the project's
	// config, and without guards, token commands or host ports. What runs
	// in it is the project's.
	Eval bool
}
