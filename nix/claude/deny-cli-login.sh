# Keeps Claude from logging gh or fj in inside the sandbox (or printing a
# login's token), with or without the guards running: a token stored inside
# is readable by all sandboxed code and used around the host proxies' popups.
cmd=$(jq -r '.tool_input.command // ""')
# Each simple command on its own, so e.g. `fj auth list; echo login` is fine.
# Global flags may come before `auth` (`fj -H codeberg.org auth login`).
login='(^|[[:space:]/])(gh|fj)[[:space:]](.*[[:space:]])?auth[[:space:]]+(login|refresh|token|add-token|add-key)([[:space:]]|$)'
while IFS= read -r seg; do
	if grep -Eq "$login" <<<"$seg"; then
		jq -n '{hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
			permissionDecisionReason: "Never log gh or fj in inside the sandbox (or print a login token): a token stored here is readable by all sandboxed code and bypasses the host proxy and its write popups. Tokens come from guards.github.tokenCommand / guards.forgejo.tokenCommands.<host>, which run on the host; tell the user to set one and restart the sandbox."
		}}'
		exit 0
	fi
done < <(sed -E 's/(\$\(|[;&|`()])+/\n/g' <<<"$cmd")
