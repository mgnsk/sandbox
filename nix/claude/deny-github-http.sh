cmd=$(jq -r '.tool_input.command // ""')
hosts='(^|[^[:alnum:].-])([[:alnum:]-]+\.)*(github\.com|githubusercontent\.com|githubassets\.com)'
clients='(^|[[:space:];&|(`])(fetch-url|curl|wget|xh|aria2c)([[:space:]]|$)'
# Check each simple command on its own, so e.g. `curl localhost; git ls-remote
# https://github.com/...` (plain git is allowed) is not a false positive.
interp='(^|[[:space:];&|(`])(python3?|node|deno)([[:space:]]|$)'
hit=
# Interpreters run inline code that may contain `;`, so check the whole command.
grep -Eq "$hosts" <<<"$cmd" && grep -Eq "$interp" <<<"$cmd" && hit=1
while [ -z "$hit" ] && IFS= read -r seg; do
	if grep -Eq "$hosts" <<<"$seg" && grep -Eq "$clients" <<<"$seg"; then
		hit=1
		break
	fi
done < <(sed -E 's/(\$\(|[;&|`()])+/\n/g' <<<"$cmd")
if [ -n "$hit" ]; then
	jq -n '{hookSpecificOutput: {
		hookEventName: "PreToolUse",
		permissionDecision: "deny",
		permissionDecisionReason: "GitHub must be accessed through the gh CLI, not HTTP clients. Use gh api, gh repo/pr/issue/release/run/gist ..., or gh api repos/OWNER/REPO/contents/PATH for raw files."
	}}'
fi
