# GitHub

All GitHub interactions (REST/GraphQL API, issues, PRs, releases,
Actions runs, gists, file contents, github.com pages) go through the
`gh` CLI - never curl, wget or other HTTP clients against github.com,
api.github.com or *.githubusercontent.com; a hook rejects those. `gh`
is authenticated through a host proxy that gates writes behind a popup.
Prefer the dedicated subcommands (`gh pr view`, `gh issue list`,
`gh release download`, `gh run view --log`, ...) and fall back to
`gh api` (`--paginate`, `--jq`, `gh api graphql`) for anything else.
For a raw file use
`gh api repos/OWNER/REPO/contents/PATH?ref=REF -H 'Accept: application/vnd.github.raw'`.
Plain `git` (clone/fetch/push) against GitHub remotes is fine.
