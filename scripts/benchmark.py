#!/usr/bin/env python3
"""Accuracy benchmark harness — run cold-box across cases and score vs ground truth.

This is the test harness behind starter idea #5 (Accuracy Benchmarking Framework)
and the seed for the submission's Accuracy Report. It reads a manifest of cases,
runs each through the agent (unless --score-only reuses prior output), scores the
findings against a ground-truth file, and emits a consolidated markdown + JSON
report with recall / required-recall / precision per case.

Manifest entry (JSON list):
  {
    "case_id": "nist-ndlc",          # output case id under CASE_OUTPUT
    "evidence_root": "/evidence",     # EVIDENCE_ROOT for the run
    "evidence_case": "nist-pc-only",  # case dir relative to evidence_root
    "ground_truth": "ground-truth/nist-ndlc.json",
    "llm": false,                      # use --llm brain (else policy/no-LLM)
    "max_iterations": 20,
    "tier": "validation"              # free-text label for the report
  }

Usage:
  python scripts/benchmark.py --manifest ground-truth/benchmark-manifest.json
  python scripts/benchmark.py --manifest ... --score-only        # don't re-run
  python scripts/benchmark.py --manifest ... --only nist-ndlc    # subset
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from postmortem_agent.scoring import ScoreReport, score_from_output_dir  # noqa: E402
from postmortem_mcp.config import case_dir  # noqa: E402


def _run_case(entry: dict, *, case_output: str) -> tuple[bool, str]:
    """Run the agent for one case. Returns (ok, message)."""
    env = dict(os.environ)
    env["EVIDENCE_ROOT"] = str(Path(entry["evidence_root"]).expanduser())
    env["CASE_OUTPUT"] = case_output
    cmd = [
        sys.executable, "-m", "postmortem_agent.cli", "run",
        "--case-id", entry["case_id"],
        "--evidence-case", entry.get("evidence_case", "."),
        "--max-iterations", str(entry.get("max_iterations", 20)),
    ]
    if entry.get("llm"):
        cmd.append("--llm")
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "run failed")[-400:]
    return True, "ok"


def _score_row(entry: dict, report: ScoreReport) -> dict:
    return {
        "case_id": entry["case_id"],
        "tier": entry.get("tier", "-"),
        "brain": "llm" if entry.get("llm") else "policy",
        "required_recall": report.required_recall,
        "recall": report.recall,
        "precision": report.precision,
        "matched": len(report.matched),
        "missed": report.missed,
        "findings": report.finding_count,
    }


def _markdown(rows: list[dict]) -> str:
    lines = [
        "# Accuracy Report — cold-box benchmark",
        "",
        f"_Generated: {datetime.now(timezone.utc).isoformat()}_",
        "",
        "Required-recall is over findings the engine is designed to surface; overall",
        "recall includes known coverage gaps (documented per case in `ground-truth/`).",
        "",
        "| Case | Tier | Brain | Required recall | Recall | Precision | Matched | Missed (required) |",
        "|------|------|-------|-----------------|--------|-----------|---------|-------------------|",
    ]
    for r in rows:
        missed = ", ".join(r["missed"]) or "—"
        lines.append(
            f"| `{r['case_id']}` | {r['tier']} | {r['brain']} | "
            f"{r['required_recall']:.2f} | {r['recall']:.2f} | {r['precision']:.2f} | "
            f"{r['matched']} | {missed} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="cold-box accuracy benchmark")
    ap.add_argument("--manifest", required=True, help="JSON manifest of cases")
    ap.add_argument("--score-only", action="store_true", help="Reuse existing output, do not re-run")
    ap.add_argument("--only", help="Comma-separated case_ids to include")
    ap.add_argument("--case-output", default=os.environ.get("CASE_OUTPUT", "/tmp/cb-cases"))
    ap.add_argument("--out", default=str(REPO_ROOT / "docs" / "ACCURACY-REPORT.md"))
    args = ap.parse_args(argv)

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    only = set(args.only.split(",")) if args.only else None

    rows: list[dict] = []
    for entry in manifest:
        if only and entry["case_id"] not in only:
            continue
        gt = REPO_ROOT / entry["ground_truth"]
        if not args.score_only:
            ok, msg = _run_case(entry, case_output=args.case_output)
            if not ok:
                print(f"[FAIL] {entry['case_id']}: {msg}", file=sys.stderr)
                rows.append({
                    "case_id": entry["case_id"], "tier": entry.get("tier", "-"),
                    "brain": "llm" if entry.get("llm") else "policy",
                    "required_recall": 0.0, "recall": 0.0, "precision": 0.0,
                    "matched": 0, "missed": ["RUN_FAILED"], "findings": 0,
                })
                continue
        out_dir = Path(args.case_output) / entry["case_id"]
        try:
            report = score_from_output_dir(out_dir, gt)
        except FileNotFoundError:
            print(f"[SKIP] {entry['case_id']}: no findings.json (run first)", file=sys.stderr)
            continue
        row = _score_row(entry, report)
        rows.append(row)
        print(f"[{entry['case_id']}] required_recall={row['required_recall']:.2f} "
              f"recall={row['recall']:.2f} precision={row['precision']:.2f}")

    md = _markdown(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md, encoding="utf-8")
    print(f"\nWrote {args.out}")
    print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
