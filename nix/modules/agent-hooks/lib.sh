# The start of every hook (agent-hooks.nix puts it first, after setting
# $agent to the agent whose hook format it speaks: claude or antigravity).
# Reads the tool call on stdin into $cmd, the command it runs in the shell.
# shellcheck disable=SC2034,SC2154 # agent is set before this, cmd read after
case $agent in
claude) cmd=$(jq -r '.tool_input.command // ""') ;;
antigravity) cmd=$(jq -r '.toolCall.args.CommandLine // ""') ;;
esac

# deny REASON: refuses the call, telling the agent why.
deny() {
	case $agent in
	claude)
		jq -n --arg r "$1" '{hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
			permissionDecisionReason: $r
		}}'
		;;
	antigravity) jq -n --arg r "$1" '{decision: "deny", reason: $r}' ;;
	esac
	exit 0
}

# pass: no decision, so the agent's own permissions decide. Antigravity
# wants a JSON object either way.
pass() {
	if [ "$agent" = antigravity ]; then
		echo '{}'
	fi
	exit 0
}
