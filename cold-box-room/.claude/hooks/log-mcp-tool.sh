#!/usr/bin/env bash
# PostToolUse hook: append cold-box-room MCP calls to the case monitor log.
set -euo pipefail

payload="$(cat)"
tool_name="$(echo "$payload" | jq -r '.tool_name // "unknown"')"
case_id="$(echo "$payload" | jq -r '.tool_input.case_id // empty')"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
records="${COLD_BOX_ROOM_RECORDS:-$ROOT/records}"

if [[ -z "$case_id" ]]; then
  case_id="$(echo "$payload" | jq -r '.. | .case_id? // empty' | head -n1)"
fi

if [[ -z "$case_id" ]]; then
  exit 0
fi

log_dir="$records/$case_id"
mkdir -p "$log_dir"
log_file="$log_dir/claude_code_monitor.log"

{
  echo "[$timestamp] MCP $tool_name case=$case_id"
  echo "$payload" | jq -c '{tool_name, tool_input, tool_response: (.tool_response | if type == "object" then {ok: (.ok // .error // .status // "done")} else . end)}' 2>/dev/null || echo "$payload"
} >> "$log_file"

exit 0
