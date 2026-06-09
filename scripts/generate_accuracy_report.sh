#!/usr/bin/env bash
# Regenerate committed accuracy snapshot for judges.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python scripts/measure_accuracy.py --agent --json-out "$ROOT/docs/accuracy-latest.json"
echo "Wrote docs/accuracy-latest.json"
