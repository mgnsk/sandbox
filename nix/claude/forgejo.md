# Forgejo

Everything on a Forgejo instance that plain `git` over SSH can't do (PRs,
issues, releases, Actions, wiki, milestones, repo settings, ...) goes
through the `fj` CLI (forgejo-cli) - not curl or other HTTP clients. API
requests to an instance with a token go through a host proxy that adds it
(the token stays outside the sandbox) and gates writes behind a popup.
`fj` comes from the project's dev shell or the user's own packages; if
it's missing, say so rather than installing it. Inside a repo with a Forgejo
remote `fj` picks the instance up from it. Run `fj <command> --help` for
subcommands (`fj pr create`, `fj issue view`, ...).
