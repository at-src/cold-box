#!/usr/bin/env python3
"""Measure cold-box verifier and agent accuracy."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "examples" / "sample-verifier"
GROUND_TRUTH = REPO / "ground-truth"

sys.path.insert(0, str(REPO))

from postmortem_verify import VerifyContext, run_verifier

EXPECTED_CONTRADICTIONS = {
    "R1": "hidden_process",
    "R2": "no_execution_trail",
    "R3": "phantom_logon",
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


def measure_verifier_rules() -> dict[str, Any]:
    pre = evidence_sha256_map(REPO / "examples" / "sample-evidence")

    ctx = VerifyContext.from_tool_payloads(
        pslist_data=_load("r1-pslist.json"),
        psscan_data=_load("r1-psscan.json"),
        amcache_data=_load("r2-amcache.json"),
        prefetch_data=_load("r5-prefetch.json"),
        mft_data=_load("r4-mft.json"),
        netscan_data=_load("r6-netscan.json"),
        security_data=_load("r3-security.json"),
        evidence_root=REPO / "examples" / "sample-evidence",
    )
    results = run_verifier(ctx)

    r2_ctx = VerifyContext.from_tool_payloads(
        pslist_data=_load("r2-pslist.json"),
        psscan_data=_load("r2-pslist.json"),
        amcache_data=_load("r2-amcache.json"),
        prefetch_data=_load("r2-prefetch.json"),
    )
    r3_ctx = VerifyContext.from_tool_payloads(
        pslist_data=_load("r3-pslist.json"),
        security_data=_load("r3-security.json"),
    )
    r6_ctx = VerifyContext.from_tool_payloads(
        pslist_data=_load("r6-pslist.json"),
        psscan_data=_load("r6-pslist.json"),
        netscan_data=_load("r6-netscan.json"),
    )

    by_id = {result.rule_id: result for result in results}
    by_id["R2"] = next(r for r in run_verifier(r2_ctx) if r.rule_id == "R2")
    by_id["R3"] = next(r for r in run_verifier(r3_ctx) if r.rule_id == "R3")
    by_id["R6"] = next(r for r in run_verifier(r6_ctx) if r.rule_id == "R6")

    fired = {rule_id for rule_id, result in by_id.items() if result.status == "contradiction"}
    expected = set(EXPECTED_CONTRADICTIONS)
    tp = fired & expected
    fn = expected - fired
    fp = fired - expected

    post = evidence_sha256_map(REPO / "examples" / "sample-evidence")
    return {
        "mode": "verifier_rules",
        "rules_expected": len(expected),
        "contradictions_fired": sorted(fired),
        "true_positives": sorted(tp),
        "false_negatives": sorted(fn),
        "false_positives": sorted(fp),
        "recall": len(tp) / max(1, len(expected)),
        "evidence_integrity_ok": pre == post,
        "details": {rule_id: by_id[rule_id].to_dict() for rule_id in sorted(by_id)},
    }


def _claim_matches(findings: list[dict[str, Any]], keywords: list[str], tags: list[str] | None = None) -> bool:
    blob_parts: list[str] = []
    for finding in findings:
        blob_parts.append(str(finding.get("claim", "")).lower())
        blob_parts.extend(str(t).lower() for t in finding.get("tags", []))
    blob = " ".join(blob_parts)
    if tags and any(tag.lower() in blob for tag in tags):
        return True
    return any(kw.lower() in blob for kw in keywords)


def measure_agent_lab(case_output: Path) -> dict[str, Any]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "postmortem_agent.cli",
            "run",
            "--case-id",
            "accuracy-lab",
            "--evidence-case",
            ".",
            "--profile",
            "lab",
            "--fixture-dir",
            str(FIXTURES),
            "--max-iterations",
            "20",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env={
            **dict(**{k: v for k, v in __import__("os").environ.items()}),
            "CASE_OUTPUT": str(case_output),
            "EVIDENCE_ROOT": str(REPO / "examples" / "sample-evidence"),
        },
        check=False,
    )
    findings_path = case_output / "accuracy-lab" / "findings.json"
    findings: list[dict[str, Any]] = []
    hallucinations = 0
    if findings_path.is_file():
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
        findings = payload.get("findings", [])
        for finding in findings:
            if finding.get("status") == "confirmed" and not finding.get("audit_ids"):
                hallucinations += 1

    gt_path = GROUND_TRUTH / "lab.json"
    expected_rows: list[dict[str, Any]] = []
    if gt_path.is_file():
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        expected_rows = gt.get("lab_expected", [])

    matched = []
    missed = []
    for row in expected_rows:
        if _claim_matches(findings, row.get("keywords", []), row.get("tags")):
            matched.append(row["id"])
        else:
            missed.append(row["id"])

    return {
        "mode": "agent_lab",
        "agent_exit_code": proc.returncode,
        "findings_count": len(findings),
        "matched_expected": matched,
        "missed_expected": missed,
        "recall": len(matched) / max(1, len(expected_rows)),
        "hallucination_count": hallucinations,
        "self_corrected": "self-correction" in (case_output / "accuracy-lab" / "progress.jsonl").read_text(encoding="utf-8")
        if (case_output / "accuracy-lab" / "progress.jsonl").is_file()
        else False,
        "findings": findings,
    }


def run_bypass_smoke() -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_mcp_bypass.py", "-q"],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        check=False,
    )
    return {"bypass_tests_pass": proc.returncode == 0, "output": proc.stdout.strip()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", action="store_true", help="Also score agent lab profile run")
    parser.add_argument("--json-out", help="Write full report JSON to path")
    args = parser.parse_args()

    report: dict[str, Any] = {
        "verifier": measure_verifier_rules(),
        "bypass": run_bypass_smoke(),
    }
    if args.agent:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            report["agent"] = measure_agent_lab(Path(tmp))

    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n", encoding="utf-8")

    ok = report["verifier"]["recall"] == 1.0 and report["verifier"]["evidence_integrity_ok"]
    ok = ok and report["bypass"]["bypass_tests_pass"]
    if args.agent:
        ok = ok and report["agent"]["recall"] >= 0.6 and report["agent"]["hallucination_count"] == 0
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
