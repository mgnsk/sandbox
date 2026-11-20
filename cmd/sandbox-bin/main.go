// sandbox-bin is the sandbox launcher, init and the guards, as subcommands
// of one binary. The `sandbox` command users run is a wrapper around
// `sandbox-bin launch` with its configuration; the rest are started by the
// launcher, on the host (the guards) or inside the sandbox (init,
// xdg-open).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/mgnsk/sandbox/internal/claudeproxy"
	"github.com/mgnsk/sandbox/internal/forgejoproxy"
	"github.com/mgnsk/sandbox/internal/ghproxy"
	"github.com/mgnsk/sandbox/internal/guard"
	"github.com/mgnsk/sandbox/internal/initcmd"
	"github.com/mgnsk/sandbox/internal/launcher"
	"github.com/mgnsk/sandbox/internal/openurl"
	"github.com/mgnsk/sandbox/internal/router"
	"github.com/mgnsk/sandbox/internal/secretservice"
	"github.com/mgnsk/sandbox/internal/sshagent"
	"github.com/mgnsk/sandbox/internal/waylandguard"
	"github.com/mgnsk/sandbox/internal/xdgopen"
)

func main() {
	os.Exit(run(context.Background(), os.Args))
}

// run runs args; the exit status.
func run(ctx context.Context, args []string) int {
	err := root().Run(ctx, args)
	var exit cli.ExitCoder
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		if msg := exit.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		return exit.ExitCode()
	default:
		fmt.Fprintln(os.Stderr, "sandbox-bin:", err)
		return 2
	}
}

// status ends a command with the exit status code.
func status(code int) error {
	if code == 0 {
		return nil
	}
	return cli.Exit("", code)
}

// usageError reports a command's usage error as prog, with exit status
// code.
func usageError(prog, hint string, code int) cli.OnUsageErrorFunc {
	return func(_ context.Context, _ *cli.Command, err error, _ bool) error {
		return cli.Exit(fmt.Sprintf("%s: %v%s", prog, err, hint), code)
	}
}

const guardsCategory = "guards (started by launch, on the host)"

func root() *cli.Command {
	return &cli.Command{
		Name:        "sandbox-bin",
		Usage:       "the sandbox launcher, init and guards",
		HideVersion: true,
		// Exit statuses are run's to set.
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				return cli.Exit(fmt.Sprintf("sandbox-bin: no command %q (see sandbox-bin --help)", cmd.Args().First()), 2)
			}
			return cli.ShowRootCommandHelp(cmd)
		},
		Commands: []*cli.Command{
			launch(),
			initCommand(),
			routerCommand(),
			xdgOpen(),
			guardCommand("ssh-agent-guard", "gate SSH agent signatures behind a popup",
				[]string{"UPSTREAM_SOCKET"}, func(ctx context.Context, a []string) error {
					return sshagent.Run(ctx, a[0])
				}),
			guardCommand("secret-service-guard", "serve a Secret Service on the sandbox's bus",
				[]string{"BUS_ADDRESS", "DATABASE"}, func(ctx context.Context, a []string) error {
					return secretservice.Run(ctx, a[0], a[1])
				}),
			guardCommand("open-url-guard", "open URLs in the host's browser after a popup",
				nil, func(ctx context.Context, _ []string) error {
					return openurl.Run(ctx)
				}),
			guardCommand("gh-api-proxy", "the GitHub API, with the token the launcher pipes in",
				nil, func(ctx context.Context, _ []string) error {
					return ghproxy.Run(ctx)
				}),
			guardCommand("forgejo-api-proxy", "Forgejo APIs, with the tokens the launcher pipes in",
				nil, func(ctx context.Context, _ []string) error {
					return forgejoproxy.Run(ctx)
				}),
			guardCommand("claude-api-proxy", "the Claude API, with the key the launcher pipes in",
				nil, func(ctx context.Context, _ []string) error {
					return claudeproxy.Run(ctx)
				}),
			guardCommand("wayland-guard", "report wl-veil's socket to the launcher (started by wl-veil)",
				nil, func(ctx context.Context, _ []string) error {
					return waylandguard.Run(ctx)
				}),
		},
	}
}

func launch() *cli.Command {
	var opts launcher.Options
	var config string
	// Flags end at the command's first word.
	stopAt := 1
	return &cli.Command{
		Name:  "launch",
		Usage: "run a command (default: a login shell) in the project's sandbox",
		UsageText: "sandbox [OPTIONS] [--] [COMMAND...]\n" +
			"sandbox-bin launch --config CONFIG.json [OPTIONS] [--] [COMMAND...]\n\n" +
			"`sandbox` runs this with its configuration.",
		StopOnNthArg: &stopAt,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Destination: &config,
				Usage: "the sandbox's configuration `FILE` (the sandbox command passes its own)", TakesFile: true},
			&cli.BoolFlag{Name: "reload", Destination: &opts.Reload,
				Usage: "evaluate sandbox.nix again, even if unchanged"},
			&cli.BoolFlag{Name: "no-project-config", Destination: &opts.NoProjectConfig,
				Usage: "ignore sandbox.nix"},
		},
		OnUsageError: usageError("sandbox", " (put -- before a command starting with -)", 1),
		Action: func(_ context.Context, cmd *cli.Command) error {
			if config == "" {
				return cli.Exit("sandbox: no --config (run `sandbox`, which passes it)", 1)
			}
			return status(launcher.Main(config, opts, cmd.Args().Slice()))
		},
	}
}

func initCommand() *cli.Command {
	return &cli.Command{
		Name:      "init",
		Usage:     "link the profiles into the home volume, then exec COMMAND (inside the sandbox)",
		ArgsUsage: "NIX_PROFILE HM_GENERATION COMMAND...",
		// Only positional arguments: the profiles may be empty, and the
		// command has options of its own.
		SkipFlagParsing: true,
		Action: func(_ context.Context, cmd *cli.Command) error {
			args := cmd.Args().Slice()
			if len(args) < 3 {
				return cli.Exit("sandbox-bin init: usage: sandbox-bin init NIX_PROFILE HM_GENERATION COMMAND...", 2)
			}
			return status(initcmd.Run(args[0], args[1], args[2:]))
		},
	}
}

func routerCommand() *cli.Command {
	return &cli.Command{
		Name:   "router",
		Usage:  "the HTTPS_PROXY inside, in front of the API guards (started by init)",
		Hidden: true,
		Action: func(context.Context, *cli.Command) error {
			if err := router.Main(); err != nil {
				return cli.Exit("sandbox-bin router: "+err.Error(), 1)
			}
			return nil
		},
	}
}

func xdgOpen() *cli.Command {
	return &cli.Command{
		Name:         "xdg-open",
		Usage:        "open an http(s) URL in the host's browser (xdg-open inside the sandbox)",
		ArgsUsage:    "URL",
		OnUsageError: usageError("xdg-open", "", xdgopen.ExitSyntax),
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 1 {
				return cli.Exit("usage: xdg-open <http(s) URL>", xdgopen.ExitSyntax)
			}
			return status(xdgopen.Run(cmd.Args().First()))
		},
	}
}

// guardCommand is the guard name, taking the arguments args, run by run
// (see package guard).
func guardCommand(name, usage string, args []string, run func(context.Context, []string) error) *cli.Command {
	argsUsage := ""
	for _, a := range args {
		argsUsage += " " + a
	}
	return &cli.Command{
		Name:         name,
		Usage:        usage,
		ArgsUsage:    argsUsage,
		Category:     guardsCategory,
		OnUsageError: usageError(name, "", 2),
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != len(args) {
				return cli.Exit(fmt.Sprintf("usage: sandbox-bin %s%s", name, argsUsage), 2)
			}
			given := cmd.Args().Slice()
			return status(guard.Main(name, func(ctx context.Context) error { return run(ctx, given) }))
		},
	}
}
