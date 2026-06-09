#!/usr/bin/env bash
# Run slow Vol3 plugins once on Ali Hadi memory; save JSON under cache/ for fast demo replay.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE="${EVIDENCE_ROOT:-/evidence}"
CASE_OUT="${CASE_OUTPUT:-$HOME/cases}"
MEM="$EVIDENCE/ali-hadi-1/memdump/memdump.mem"
CACHE="$CASE_OUT/ali-hadi-1/cache"
CASE_ID="ali-hadi-cache"
VOL="${VOL3:-$ROOT/bin/vol}"

export EVIDENCE_ROOT="$EVIDENCE"
export CASE_OUTPUT="$CASE_OUT"
export VOL3="$VOL"

if [[ ! -f "$MEM" ]]; then
  echo "Missing $MEM" >&2
  exit 1
fi

mkdir -p "$CACHE"
cd "$ROOT"
source .venv/bin/activate 2>/dev/null || true

run_tool() {
  local tool="$1"
  local out="$CACHE/${tool}.json"
  echo "Running $tool (slow) ..."
  python3 - <<PY
import json
from postmortem_mcp.tools.memory import (
    mem_cmdline,
    mem_malfind,
    mem_netscan,
    mem_pslist,
    mem_psscan,
    mem_pstree,
)

TOOLS = {
    "mem_pslist": mem_pslist,
    "mem_psscan": mem_psscan,
    "mem_cmdline": mem_cmdline,
    "mem_malfind": mem_malfind,
    "mem_netscan": mem_netscan,
    "mem_pstree": mem_pstree,
}
fn = TOOLS["$tool"]
result = fn(
    case_id="$CASE_ID",
    memory_relpath="ali-hadi-1/memdump/memdump.mem",
    iteration=0,
)
path = "$out"
with open(path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
print(f"Wrote {path}")
PY
}

for t in mem_pslist mem_psscan mem_cmdline mem_malfind mem_netscan mem_pstree; do
  run_tool "$t"
done

echo "Cache complete under $CACHE"
