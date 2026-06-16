#!/usr/bin/env bash
# Live monitor for a cold-box-room case while Claude Code (or native hallway) runs.
# Usage: monitor_case.sh CASE_ID [records_root]
set -euo pipefail

CASE_ID="${1:?usage: monitor_case.sh CASE_ID [records_root]}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECORDS_ROOT="${2:-${COLD_BOX_ROOM_RECORDS:-$ROOT/records}}"
CASE_DIR="$RECORDS_ROOT/$CASE_ID"
MONITOR_LOG="$CASE_DIR/claude_code_monitor.log"

mkdir -p "$CASE_DIR"
touch "$MONITOR_LOG"

print_status() {
  local hall room
  if [[ -f "$CASE_DIR/hallway.json" ]]; then
    room="$(python3 - <<PY 2>/dev/null || echo "?"
import json
from pathlib import Path
p = Path("$CASE_DIR/hallway.json")
print(json.loads(p.read_text()).get("current_room", "?"))
PY
)"
    hall="room=$room"
  else
    hall="no hallway.json yet"
  fi
  local audit_n tool_n
  audit_n="$(wc -l < "$CASE_DIR/audit.jsonl" 2>/dev/null || echo 0)"
  tool_n="$(wc -l < "$CASE_DIR/tool_log.jsonl" 2>/dev/null || echo 0)"
  printf '[%s] %s | audit=%s tool_log=%s | dir=%s\n' \
    "$(date -u +%H:%M:%S)" "$hall" "$audit_n" "$tool_n" "$CASE_DIR"
}

echo "Monitoring case: $CASE_ID"
echo "Records:         $CASE_DIR"
echo "Monitor log:     $MONITOR_LOG"
echo "Press Ctrl+C to stop."
echo ""

print_status

WATCH_FILES=()
for f in audit.jsonl tool_log.jsonl layer2_tool_log.jsonl hallway.json plan_a.py plan_b.py; do
  [[ -f "$CASE_DIR/$f" ]] && WATCH_FILES+=("$CASE_DIR/$f")
done

if [[ ${#WATCH_FILES[@]} -eq 0 ]]; then
  echo "Waiting for case files under $CASE_DIR ..."
  while [[ ! -f "$CASE_DIR/audit.jsonl" && ! -f "$CASE_DIR/hallway.json" ]]; do
    sleep 2
  done
  WATCH_FILES=("$CASE_DIR")
fi

(
  while true; do
    sleep 15
    print_status >> "$MONITOR_LOG"
    print_status
  done
) &
HEARTBEAT_PID=$!
trap 'kill "$HEARTBEAT_PID" 2>/dev/null || true' EXIT

if command -v inotifywait >/dev/null 2>&1; then
  inotifywait -m -e modify,create,move "$CASE_DIR" 2>/dev/null | while read -r _ _ file; do
    base="$(basename "$file")"
    case "$base" in
      audit.jsonl|tool_log.jsonl|layer2_tool_log.jsonl|hallway.json|*.md|plan_*.py)
        line="$(tail -n 1 "$CASE_DIR/$base" 2>/dev/null | head -c 200 || true)"
        msg="$(date -u +%H:%M:%S) CHANGE $base: ${line:-<updated>}"
        echo "$msg" | tee -a "$MONITOR_LOG"
        ;;
    esac
  done
else
  tail -F "$CASE_DIR/audit.jsonl" "$CASE_DIR/tool_log.jsonl" "$CASE_DIR/hallway.json" 2>/dev/null | while read -r line; do
    msg="$(date -u +%H:%M:%S) $line"
    echo "$msg" | tee -a "$MONITOR_LOG"
  done
fi
