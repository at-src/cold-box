#!/usr/bin/env bash
# One-command synthetic demo: R1 fires, agent self-corrects, writes audit + progress logs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CASE_OUTPUT="${CASE_OUTPUT:-/tmp/cold-box-demo}"
CASE_ID="${CASE_ID:-synthetic-demo}"
rm -rf "${CASE_OUTPUT}/${CASE_ID}"
source .venv/bin/activate 2>/dev/null || true
cold-box-agent run \
  --case-id "$CASE_ID" \
  --evidence-case synthetic-r1 \
  --synthetic \
  --fixture-dir "$ROOT/examples/sample-verifier"
echo "--- audit ---"
cold-box-audit summary "${CASE_OUTPUT}/${CASE_ID}/audit.jsonl"
echo "--- progress (grep self-correction) ---"
rg self-correction "${CASE_OUTPUT}/${CASE_ID}/progress.jsonl" || true
echo "--- findings ---"
cat "${CASE_OUTPUT}/${CASE_ID}/findings.json"
echo "--- report (head) ---"
head -n 30 "${CASE_OUTPUT}/${CASE_ID}/report.md"
echo "--- bypass guardrails ---"
python -m pytest tests/test_mcp_bypass.py -q
