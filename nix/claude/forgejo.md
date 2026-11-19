# Forgejo

**NEVER run `fj auth login` inside the sandbox.** A token inside is
readable by all sandboxed code and bypasses the host proxy's write popups.
If `fj` has no access, tell the user to set
`guards.forgejo.tokenCommands.<host>` and restart.

Everything on a Forgejo instance that plain `git` over SSH can't do (PRs,
issues, releases, Actions, wiki, milestones, repo settings, ...) goes
through the `fj` CLI (forgejo-cli) - not curl or other HTTP clients. API
requests to an instance with a token command go through a host proxy that
adds its token (which stays outside the sandbox) and gates writes behind a
popup. An instance without one is reached without a token: `fj` only sees
what is public there. Say so, and that the fix is
`guards.forgejo.tokenCommands.<host>` in the project's `sandbox.nix` or
`.sandbox.yml` (or the user's sandbox config) and a restart.
`fj` comes from the project's dev shell or the user's own packages; if
it's missing, say so rather than installing it. Inside a repo with a Forgejo
remote `fj` picks the instance up from it. Run `fj <command> --help` for
subcommands (`fj pr create`, `fj issue view`, ...).
