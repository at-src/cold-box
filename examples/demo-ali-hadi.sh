#!/usr/bin/env bash
# Ali Hadi hero case demo (cached memory replay when cache exists).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export EVIDENCE_ROOT="${EVIDENCE_ROOT:-/evidence}"
export CASE_OUTPUT="${CASE_OUTPUT:-$HOME/cases}"
CACHE="${CASE_OUTPUT}/ali-hadi-1/cache"
EXTRACTED="${CASE_OUTPUT}/ali-hadi-1/extracted"
CASE_ID="${CASE_ID:-ali-hadi-demo}"
source .venv/bin/activate 2>/dev/null || true

if [[ ! -d "$CACHE" ]]; then
  echo "No cache at $CACHE — run scripts/cache_ali_hadi_memory.sh first (slow)." >&2
  exit 1
fi

cold-box-agent run \
  --case-id "$CASE_ID" \
  --evidence-case ali-hadi-1 \
  --memory ali-hadi-1/memdump/memdump.mem \
  --from-cache "$CACHE" \
  --extracted-root "$EXTRACTED" \
  --max-iterations 15

cold-box-audit summary "${CASE_OUTPUT}/${CASE_ID}/audit.jsonl"
head -n 40 "${CASE_OUTPUT}/${CASE_ID}/report.md"
