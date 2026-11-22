package launcher

// Options are the launcher's own, from sandbox-bin launch's flags.
type Options struct {
	// Ignore the project's .sandbox.yml.
	NoProjectConfig bool
}
