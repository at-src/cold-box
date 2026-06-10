#!/usr/bin/env bash
# Hero runs: DART sample + Ali Hadi with LLM reasoner (requires ANTHROPIC_API_KEY).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]] || [[ "$ANTHROPIC_API_KEY" == *paste* ]]; then
  echo "ANTHROPIC_API_KEY not set — skipping LLM hero runs." >&2
  echo "Export a key and re-run: export ANTHROPIC_API_KEY=..." >&2
  exit 0
fi

echo "=== DART sample-evidence (LLM) ==="
EVIDENCE_ROOT=/opt/ref/agentic-dart/examples/sample-evidence \
  cold-box-agent run --case-id hero-dart --evidence-case . --llm --max-iterations 30

echo "=== DART score ==="
cold-box-agent score \
  --output-dir "${CASE_OUTPUT:-/tmp/bench-report}/hero-dart" \
  --ground-truth ground-truth/dart-sample-evidence.json \
  --min-recall 0.75 \
  --self-corrected || true

echo "=== Ali Hadi (LLM + cache + widened extract) ==="
EXTRACT="${HOME}/cases/ali-hadi-1/extracted"
if [[ -d "$EXTRACT/web" ]]; then
  EVIDENCE_ROOT=/evidence \
    cold-box-agent run --case-id hero-ali --evidence-case ali-hadi-1 \
    --from-cache "${HOME}/cases/ali-hadi-1/cache" \
    --extracted-root "$EXTRACT" \
    --llm --max-iterations 35

  cold-box-agent score \
    --output-dir "${CASE_OUTPUT:-/tmp/bench-report}/hero-ali" \
    --ground-truth ground-truth/ali-hadi-1.json \
    --min-recall 0.4 || true
else
  echo "Ali extract missing web overlay — run scripts/widen_ali_extract.sh first" >&2
fi

echo "Done. Check narrative.md under each case output dir."
