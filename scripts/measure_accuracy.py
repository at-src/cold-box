#!/usr/bin/env python3
"""Measure cold-box verifier accuracy on bundled synthetic fixtures."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "examples" / "sample-verifier"

sys.path.insert(0, str(REPO))

from postmortem_verify import VerifyContext, run_verifier

# Expected contradictions on the reference fixture set.
EXPECTED_CONTRADICTIONS = {
    "R1": "hidden_process",
    "R2": "no_execution_trail",
    "R4": "timestomp",
    "R5": "ghost_binary",
    "R6": "orphan_connection",
}


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def evidence_sha256_map(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def main() -> int:
    pre = evidence_sha256_map(REPO / "examples" / "sample-evidence")

    ctx = VerifyContext.from_tool_payloads(
        pslist_data=_load("r1-pslist.json"),
        psscan_data=_load("r1-psscan.json"),
        amcache_data=_load("r2-amcache.json"),
        prefetch_data=_load("r5-prefetch.json"),
        mft_data=_load("r4-mft.json"),
        netscan_data=_load("r6-netscan.json"),
        evidence_root=REPO / "examples" / "sample-evidence",
    )
    # R2 needs ghostrunner pslist; R6 needs clean pslist — run focused passes.
    results = run_verifier(ctx)

    r2_ctx = VerifyContext.from_tool_payloads(
        pslist_data=_load("r2-pslist.json"),
        psscan_data=_load("r2-pslist.json"),
        amcache_data=_load("r2-amcache.json"),
        prefetch_data=_load("r2-prefetch.json"),
    )
    r6_ctx = VerifyContext.from_tool_payloads(
        pslist_data=_load("r6-pslist.json"),
        psscan_data=_load("r6-pslist.json"),
        netscan_data=_load("r6-netscan.json"),
    )

    by_id = {result.rule_id: result for result in results}
    by_id["R2"] = run_verifier(r2_ctx)[1]
    by_id["R6"] = run_verifier(r6_ctx)[4]

    fired = {rule_id for rule_id, result in by_id.items() if result.status == "contradiction"}
    expected = set(EXPECTED_CONTRADICTIONS)
    tp = fired & expected
    fn = expected - fired
    fp = fired - expected

    post = evidence_sha256_map(REPO / "examples" / "sample-evidence")
    integrity_ok = pre == post

    report = {
        "rules_expected": len(expected),
        "contradictions_fired": sorted(fired),
        "true_positives": sorted(tp),
        "false_negatives": sorted(fn),
        "false_positives": sorted(fp),
        "recall": len(tp) / max(1, len(expected)),
        "evidence_integrity_ok": integrity_ok,
        "details": {rule_id: by_id[rule_id].to_dict() for rule_id in sorted(by_id)},
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    if fn or fp or not integrity_ok:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
