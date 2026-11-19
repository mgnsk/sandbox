package launcher

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/mgnsk/sandbox/internal/hostname"
)

type options struct {
	reload          bool
	noProjectConfig bool
	claudeAPIKey    bool
	ghToken         bool
	fjToken         string // The Forgejo host, normalized.
}

// flags are the launcher's own options, set into o.
func flags(o *options) *flag.FlagSet {
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.reload, "reload", false, "evaluate sandbox.nix and ~/.config/sandbox/config.nix again, even if unchanged")
	fs.BoolVar(&o.noProjectConfig, "no-project-config", false, "ignore sandbox.nix")
	fs.BoolVar(&o.claudeAPIKey, "claude-api-key", false, "set this project's Claude API key and exit")
	fs.BoolVar(&o.ghToken, "gh-token", false, "set this project's GitHub token and exit")
	fs.StringVar(&o.fjToken, "fj-token", "", "set this project's token for a Forgejo `host` and exit")
	return fs
}

// printUsage writes the usage and the options to w.
func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: sandbox [OPTIONS] [--] [COMMAND...]")
	fs := flags(&options{})
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// parseOptions takes the launcher's own leading options; the command after
// them. flag.ErrHelp for -h.
func parseOptions(args []string) (options, []string, error) {
	var o options
	fs := flags(&o)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return o, nil, err
		}
		return o, nil, fmt.Errorf("%w (put -- before a command starting with -)", err)
	}
	if o.fjToken != "" {
		host, ok := hostname.Normalize(o.fjToken)
		if !ok {
			return o, nil, fmt.Errorf("not a Forgejo host: %s", o.fjToken)
		}
		o.fjToken = host
	}
	return o, fs.Args(), nil
}
