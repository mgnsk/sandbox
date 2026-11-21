# GitHub

**NEVER run `gh auth login` (or set a real `GH_TOKEN`) inside the sandbox.**
A token inside is readable by all sandboxed code and bypasses the host
proxy's write popups. If `gh` has no access, tell the user to set
`guards.github.tokenCommand` and restart.

All GitHub interactions (REST/GraphQL API, issues, PRs, releases,
Actions runs, gists, file contents, github.com pages) go through the
`gh` CLI - never curl, wget or other HTTP clients against github.com,
api.github.com or *.githubusercontent.com.
`gh` comes from the project's dev shell or the user's own packages; if
it's missing, say so rather than installing it.

Whether `gh` is authenticated depends on how the sandbox was started:

- `$GH_TOKEN` is `sandbox-placeholder`: a token command is set, so a host
  proxy adds the real token to API requests and gates writes behind a
  popup. A hook may reject HTTP clients against GitHub.
- `$GH_TOKEN` is unset: no token command, so no proxy and no token. `gh`
  only reaches what is public, and writes fail. Say so, and that the fix is
  `guards.github.tokenCommand` in the project's flake (the `sandbox` of
  `sandbox.lib.mkShell`) or `.sandbox.yml` (or the user's sandbox
  config) and a restart.

Prefer the dedicated subcommands (`gh pr view`, `gh issue list`,
`gh release download`, `gh run view --log`, ...) and fall back to
`gh api` (`--paginate`, `--jq`, `gh api graphql`) for anything else.
For a raw file use
`gh api repos/OWNER/REPO/contents/PATH?ref=REF -H 'Accept: application/vnd.github.raw'`.
Plain `git` (clone/fetch/push) against GitHub remotes is fine.
