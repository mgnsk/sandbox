# Forgejo

Everything on a Forgejo instance that plain `git` over SSH can't do (PRs,
issues, releases, Actions, wiki, milestones, repo settings, ...) goes
through the `fj` CLI (forgejo-cli) - never curl or other HTTP clients
against it; the token lives only on the host, so they get no auth anyway.
Writes are gated behind a popup on the host. Inside a repo with a Forgejo
remote `fj` picks the instance up from it. Run `fj <command> --help` for
subcommands (`fj pr create`, `fj issue view`, ...).
