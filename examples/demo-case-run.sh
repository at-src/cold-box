#!/usr/bin/env bash
# Disk + verifier demo on bundled cold-box sample-evidence (original lab case).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export EVIDENCE_ROOT="$ROOT/examples/sample-evidence"
export CASE_OUTPUT="${CASE_OUTPUT:-/tmp/cold-box-case-demo}"
export CASE_ID="${CASE_ID:-cold-box-lab-demo}"
rm -rf "${CASE_OUTPUT}/${CASE_ID}"
source .venv/bin/activate 2>/dev/null || true

python <<PY
import json
import os
from pathlib import Path

ROOT = Path("${ROOT}")
os.environ["EVIDENCE_ROOT"] = str(ROOT / "examples" / "sample-evidence")
os.environ["CASE_OUTPUT"] = os.environ.get("CASE_OUTPUT", "/tmp/cold-box-case-demo")

from postmortem_mcp.tools.disk import disk_detect_timestomp, disk_parse_prefetch
from postmortem_mcp.tools.evidence import evidence_manifest

case_id = os.environ.get("CASE_ID", "cold-box-lab-demo")

manifest = evidence_manifest(case_id, ".", iteration=1)
prefetch = disk_parse_prefetch(
    case_id,
    "disk/Windows/Prefetch/COLDLOADER.EXE-B1C2D3E4.pf",
    iteration=2,
)
timestomp = disk_detect_timestomp(
    case_id,
    "disk/\$MFT.csv",
    iteration=3,
    max_records=5000,
)

assert manifest.get("ok"), manifest
assert prefetch.get("ok"), prefetch
assert timestomp.get("ok"), timestomp

print("manifest files:", manifest["data"]["file_count"])
print("prefetch executable:", prefetch["data"]["prefetch"]["executable"])
print("timestomp findings:", timestomp["data"]["findings_count"])

out = Path(os.environ["CASE_OUTPUT"]) / case_id
out.mkdir(parents=True, exist_ok=True)
(out / "disk-tools.json").write_text(
    json.dumps(
        {"manifest": manifest, "prefetch": prefetch, "timestomp": timestomp},
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

cold-box-verify run \
  --pslist "$ROOT/examples/sample-verifier/r6-pslist.json" \
  --psscan "$ROOT/examples/sample-verifier/r6-pslist.json" \
  --prefetch "$ROOT/examples/sample-verifier/r5-prefetch.json" \
  --mft "$ROOT/examples/sample-verifier/r4-mft.json" \
  --netscan "$ROOT/examples/sample-verifier/r6-netscan.json" \
  --evidence-root "$EVIDENCE_ROOT" \
  || true

echo "--- measure_accuracy ---"
python scripts/measure_accuracy.py
echo "--- bypass ---"
python -m pytest tests/test_mcp_bypass.py -q
