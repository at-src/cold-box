#!/usr/bin/env bash
# Multi-finding lab demo: R1 self-correction + R3/R4/R5/R6 correlation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export EVIDENCE_ROOT="$ROOT/examples/sample-evidence"
export CASE_OUTPUT="${CASE_OUTPUT:-/tmp/cold-box-lab-demo}"
CASE_ID="${CASE_ID:-cold-box-lab-run}"
rm -rf "${CASE_OUTPUT}/${CASE_ID}"
source .venv/bin/activate 2>/dev/null || true

cold-box-agent run \
  --case-id "$CASE_ID" \
  --evidence-case . \
  --profile lab \
  --fixture-dir "$ROOT/examples/sample-verifier" \
  --max-iterations 25

echo "--- findings ---"
cat "${CASE_OUTPUT}/${CASE_ID}/findings.json"
echo "--- self-correction ---"
rg self-correction "${CASE_OUTPUT}/${CASE_ID}/progress.jsonl" || true
python scripts/measure_accuracy.py --agent
