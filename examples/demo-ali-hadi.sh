#!/usr/bin/env bash
# Ali Hadi Case #1 hero demo — real cached memory + extracted disk (~15s).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export EVIDENCE_ROOT="${EVIDENCE_ROOT:-/evidence}"
export CASE_OUTPUT="${CASE_OUTPUT:-$HOME/cases}"
CACHE="${CASE_OUTPUT}/ali-hadi-1/cache"
CASE_ID="${CASE_ID:-ali-hadi-demo}"
source .venv/bin/activate 2>/dev/null || true

if [[ ! -d "$CACHE" ]]; then
  echo "Missing cache at $CACHE — run: bash scripts/cache_ali_hadi_memory.sh" >&2
  exit 1
fi
if [[ ! -f "${CASE_OUTPUT}/ali-hadi-1/extracted/\$MFT" ]]; then
  echo "Missing extracted disk — run: bash scripts/extract_ali_hadi_disk.sh" >&2
  exit 1
fi

rm -rf "${CASE_OUTPUT}/${CASE_ID}"
cold-box-agent run \
  --case-id "$CASE_ID" \
  --evidence-case ali-hadi-1 \
  --memory ali-hadi-1/memdump/memdump.mem \
  --profile ali-hadi \
  --from-cache "$CACHE" \
  --artifact-root "${CASE_OUTPUT}/ali-hadi-1" \
  --max-iterations 20

echo "--- findings ---"
python3 -c "import json,sys; f=json.load(open('${CASE_OUTPUT}/${CASE_ID}/findings.json')); print(len(f['findings']),'findings'); [print(' ',x.get('tags'), x['claim'][:75]) for x in f['findings']]"
echo "--- self-correction ---"
rg self-correction "${CASE_OUTPUT}/${CASE_ID}/progress.jsonl" || true
cold-box-audit summary "${CASE_OUTPUT}/${CASE_ID}/audit.jsonl"
