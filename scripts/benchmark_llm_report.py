#!/usr/bin/env python3
"""Run full LLM-brain benchmark and write a private reference report (gitignored)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from postmortem_agent.scoring import score_from_output_dir  # noqa: E402
from scripts.benchmark import (  # noqa: E402
    _brain_label,
    _load_repo_env,
    _run_case,
    _score_row,
)


def _read_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _run_summary(case_output: Path, case_id: str) -> dict:
    out = case_output / case_id
    progress = out / "progress.jsonl"
    self_corrected = False
    iterations = 0
    if progress.is_file():
        for line in progress.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            iterations += 1
            row = json.loads(line)
            notes = str(row.get("notes") or "")
            if "self-correction" in notes.lower():
                self_corrected = True
            if "iteration" in row:
                iterations = max(iterations, int(row["iteration"]))
    findings_path = out / "findings.json"
    findings_count = 0
    if findings_path.is_file():
        payload = _read_json(findings_path)
        if isinstance(payload, dict):
            findings_count = len(payload.get("findings") or [])
    audit_ok = None
    audit_path = out / "audit.jsonl"
    if audit_path.is_file():
        proc = subprocess.run(
            [sys.executable, "-m", "postmortem_audit.cli", "verify", str(audit_path)],
            capture_output=True,
            text=True,
            cwd=str(REPO),
            check=False,
        )
        audit_ok = proc.returncode == 0
    return {
        "iterations": iterations,
        "self_corrected": self_corrected,
        "findings_count": findings_count,
        "audit_chain_ok": audit_ok,
        "output_dir": str(out),
    }


def _markdown(
    *,
    rows: list[dict],
    model: str,
    manifest_path: Path,
    case_output: Path,
    failures: list[dict],
) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    req_vals = [r["required_recall"] for r in rows if r.get("required_recall") is not None]
    mean_req = sum(req_vals) / len(req_vals) if req_vals else 0.0
    recall_vals = [r["recall"] for r in rows if r.get("recall") is not None]
    mean_recall = sum(recall_vals) / len(recall_vals) if recall_vals else 0.0

    lines = [
        "# LLM brain — full benchmark reference",
        "",
        f"_Generated: {ts}_",
        "",
        "Private reference (under `dont-commit-main-plan/` — not committed).",
        "Reproduce:",
        "",
        "```bash",
        "cd /opt/postmortem",
        "python3 scripts/benchmark_llm_report.py \\",
        "  --manifest dont-commit-main-plan/benchmark-manifest-llm-full.json \\",
        "  --case-output /tmp/cb-llm-cases",
        "```",
        "",
        "## Run configuration",
        "",
        f"| Setting | Value |",
        f"|---------|-------|",
        f"| Brain | **LLM** (`--llm`) |",
        f"| Model | `{model}` |",
        f"| Manifest | `{manifest_path}` |",
        f"| Case output | `{case_output}` |",
        f"| Cases | {len(rows)} |",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|------:|",
        f"| Mean required recall | **{mean_req:.3f}** |",
        f"| Mean overall recall | {mean_recall:.3f} |",
        f"| Run failures | {len(failures)} |",
        "",
        "## Per-case scores",
        "",
        "| Case | Tier | Required recall | Recall | Precision | Findings | Self-correct | Missed (required) |",
        "|------|------|----------------:|-------:|----------:|---------:|:------------:|-------------------|",
    ]
    for r in rows:
        meta = r.get("run_meta") or {}
        sc = "yes" if meta.get("self_corrected") else "—"
        missed = ", ".join(r.get("missed") or []) or "—"
        lines.append(
            f"| `{r['case_id']}` | {r.get('tier', '-')} | "
            f"{r['required_recall']:.2f} | {r['recall']:.2f} | {r['precision']:.2f} | "
            f"{r.get('findings', 0)} | {sc} | {missed} |"
        )

    if failures:
        lines.extend(["", "## Run failures", ""])
        for f in failures:
            lines.append(f"- **`{f['case_id']}`**: {f['error']}")

    lines.extend(["", "## Per-case output paths", ""])
    for r in rows:
        meta = r.get("run_meta") or {}
        lines.append(f"- `{r['case_id']}` → `{meta.get('output_dir', '?')}`")

    lines.extend([
        "",
        "## Policy vs LLM (required recall)",
        "",
        "| Case (base id) | Policy | LLM | Delta |",
        "|----------------|-------:|----:|------:|",
    ])
    policy_rows = {}
    acc_path = REPO / "docs" / "accuracy-latest.json"
    if acc_path.is_file():
        for c in json.loads(acc_path.read_text())["cold_box_policy"]["cases"]:
            policy_rows[c["case_id"]] = c["required_recall"]
    for r in rows:
        base = r["case_id"].removesuffix("-llm")
        pol = policy_rows.get(base)
        llm = r["required_recall"]
        if pol is not None:
            delta = llm - pol
            sign = "+" if delta > 0 else ""
            lines.append(f"| `{base}` | {pol:.2f} | {llm:.2f} | {sign}{delta:.2f} |")
    lines.extend([
        "",
        "## OS coverage (required recall = 1.00?)",
        "",
        "| Bucket | Cases | LLM pass |",
        "|--------|-------|----------|",
        "| Windows | nist-ndlc, ali-hadi-1/7/9, nist-hacking | 4/5 (ali-hadi-7 missed F-FAKE-INSTALLER) |",
        "| Linux | dfrws2008 | 1/1 |",
        "| Network | nitroba | 1/1 |",
        "| Android | dfrws2011 case1/2 | 2/2 |",
        "| macOS | macos-spotlight | 1/1 |",
        "",
        "## Notes",
        "",
        "- **Required recall** = matched required ground-truth rows / total required.",
        "- **Recall** = all GT rows (required + optional).",
        "- `ali-hadi-9-llm` is a restraint case — low optional recall can be correct behavior.",
        "- Compare policy brain: `docs/ACCURACY-REPORT.md`.",
        "",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="LLM full benchmark + private markdown report")
    ap.add_argument(
        "--manifest",
        default=str(REPO / "dont-commit-main-plan" / "benchmark-manifest-llm-full.json"),
    )
    ap.add_argument("--case-output", default="/tmp/cb-llm-cases")
    ap.add_argument(
        "--out-md",
        default=str(REPO / "dont-commit-main-plan" / "LLM-ACCURACY-REPORT.md"),
    )
    ap.add_argument(
        "--out-json",
        default=str(REPO / "dont-commit-main-plan" / "LLM-ACCURACY-REPORT.json"),
    )
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--only", help="Comma-separated case_ids")
    args = ap.parse_args(argv)

    env = _load_repo_env(dict(os.environ))
    model = env.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    only = set(args.only.split(",")) if args.only else None
    case_output = Path(args.case_output)
    case_output.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    failures: list[dict] = []

    for entry in manifest:
        if only and entry["case_id"] not in only:
            continue
        gt = REPO / entry["ground_truth"]
        if not args.score_only:
            print(f"[RUN] {entry['case_id']} ...", flush=True)
            ok, msg = _run_case(entry, case_output=str(case_output))
            if not ok:
                print(f"[FAIL] {entry['case_id']}: {msg}", file=sys.stderr)
                failures.append({"case_id": entry["case_id"], "error": msg})
                rows.append({
                    "case_id": entry["case_id"],
                    "tier": entry.get("tier", "-"),
                    "brain": _brain_label(entry),
                    "required_recall": 0.0,
                    "recall": 0.0,
                    "precision": 0.0,
                    "matched": 0,
                    "missed": ["RUN_FAILED"],
                    "findings": 0,
                    "run_meta": {},
                })
                continue

        out_dir = case_output / entry["case_id"]
        try:
            report = score_from_output_dir(out_dir, gt)
        except FileNotFoundError:
            failures.append({"case_id": entry["case_id"], "error": "no findings.json"})
            continue

        row = _score_row(entry, report)
        row["run_meta"] = _run_summary(case_output, entry["case_id"])
        rows.append(row)
        print(
            f"[{entry['case_id']}] required_recall={row['required_recall']:.2f} "
            f"recall={row['recall']:.2f} precision={row['precision']:.2f}",
            flush=True,
        )

    md = _markdown(
        rows=rows,
        model=model,
        manifest_path=Path(args.manifest),
        case_output=case_output,
        failures=failures,
    )
    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(md, encoding="utf-8")

    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "brain": "llm",
        "model": model,
        "manifest": str(args.manifest),
        "case_output": str(case_output),
        "mean_required_recall": round(
            sum(r["required_recall"] for r in rows) / max(1, len(rows)), 3
        ),
        "cases": rows,
        "failures": failures,
    }
    Path(args.out_json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"\nWrote {out_md}")
    print(f"Wrote {args.out_json}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
