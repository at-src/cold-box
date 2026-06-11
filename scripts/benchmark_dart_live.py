#!/usr/bin/env python3
"""Run Agentic-DART live (LLM) on cold-box manifest cases; score with cold-box GT."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DART = Path("/opt/ref/agentic-dart")
OUT_ROOT = Path("/tmp/dart-llm-bench")

sys.path.insert(0, str(REPO))
from postmortem_agent.scoring import ScoreReport, score_findings  # noqa: E402
from scripts.benchmark import _load_repo_env  # noqa: E402

MANIFEST = REPO / "dont-commit-main-plan" / "benchmark-manifest-llm-full.json"

# Map cold-box base case_id -> (evidence_root, evidence_subdir under root)
CASE_EVIDENCE: dict[str, tuple[str, str]] = {
    "nist-ndlc": ("/evidence", "nist-pc-only"),
    "ali-hadi-1": ("/evidence", "ali-hadi-1"),
    "nitroba": ("/evidence", "nitroba"),
    "dfrws2008": ("/evidence", "dfrws2008/evidence/response_data"),
    "ali-hadi-7": ("/evidence", "ali-hadi-7"),
    "ali-hadi-9": ("/evidence", "ali-hadi-9"),
    "nist-hacking": ("/evidence", "nist-hacking"),
    "dart-sample-evidence": (
        "/opt/ref/agentic-dart/examples/sample-evidence",
        ".",
    ),
    "dfrws2011-android-case1": ("/evidence", "dfrws2011-android/case1-extract"),
    "dfrws2011-android-case2": ("/evidence", "dfrws2011-android/case2-extract"),
    "macos-spotlight": ("/evidence", "macos-spotlight/c18-spotlight"),
}


def _parse_report_findings(out_dir: Path) -> list[dict]:
    """Extract findings from DART live_transcript REPORT block or summary."""
    findings: list[dict] = []
    summary = out_dir / "live_summary.json"
    if summary.is_file():
        payload = json.loads(summary.read_text(encoding="utf-8"))
        for i, row in enumerate(payload.get("findings") or []):
            text = " ".join(
                str(row.get(k, ""))
                for k in ("id", "title", "evidence_summary", "description")
            )
            findings.append(
                {
                    "id": str(row.get("id") or f"dart-{i}"),
                    "claim": text,
                    "status": "confirmed",
                    "tags": [],
                }
            )
    transcript = out_dir / "live_transcript.txt"
    if transcript.is_file():
        text = transcript.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"REPORT:\s*(\{.*\})\s*$", text, re.DOTALL | re.MULTILINE)
        if m:
            try:
                report = json.loads(m.group(1))
                for i, row in enumerate(report.get("findings") or []):
                    blob = json.dumps(row) if isinstance(row, dict) else str(row)
                    findings.append(
                        {
                            "id": f"report-{i}",
                            "claim": blob,
                            "status": "confirmed",
                            "tags": [],
                        }
                    )
                hyp = report.get("primary_hypothesis") or report.get("hypothesis")
                if hyp:
                    findings.append(
                        {
                            "id": "report-hypothesis",
                            "claim": str(hyp),
                            "status": "inference",
                            "tags": [],
                        }
                    )
            except json.JSONDecodeError:
                pass
        # Always add full transcript as one finding blob for keyword recall
        # (matches prior head-to-head methodology for DART live).
        findings.append(
            {
                "id": "transcript-blob",
                "claim": text[-120_000:],
                "status": "confirmed",
                "tags": [],
            }
        )
    return findings


def _self_corrected(out_dir: Path) -> bool:
    transcript = out_dir / "live_transcript.txt"
    if transcript.is_file():
        t = transcript.read_text(encoding="utf-8", errors="replace").lower()
        if "self-correction" in t or "contradiction" in t or "revising" in t:
            return True
    return False


def _run_dart_live(
    *,
    case_id: str,
    evidence_root: str,
    max_iterations: int,
    model: str,
    env: dict[str, str],
) -> tuple[bool, str, Path]:
    out_dir = OUT_ROOT / f"{case_id}-dart-live"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_env = dict(env)
    run_env["DART_EVIDENCE_ROOT"] = evidence_root
    run_env["DART_MODEL"] = model
    run_env["PYTHONPATH"] = ":".join(
        [
            str(DART / "dart_mcp" / "src"),
            str(DART / "dart_agent" / "src"),
            str(DART / "dart_audit" / "src"),
        ]
    )
    cmd = [
        sys.executable,
        "-m",
        "dart_agent.live",
        "--case",
        f"{case_id}-dart-live",
        "--out",
        str(out_dir),
        "--model",
        model,
        "--max-iterations",
        str(max_iterations),
        "--prompt",
        (
            "Investigate all evidence under DART_EVIDENCE_ROOT. "
            "Use forensic MCP tools systematically. Report confirmed compromise "
            "indicators with audit-backed reasoning. End with a REPORT JSON block."
        ),
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(DART),
        env=run_env,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-500:]
        return False, tail, out_dir
    return True, "ok", out_dir


def _run_dart_cfreds() -> dict:
    proc = subprocess.run(
        [sys.executable, "scripts/measure_cfreds.py"],
        cwd=str(DART),
        capture_output=True,
        text=True,
        timeout=120,
    )
    text = proc.stdout or ""
    strict = lenient = None
    for line in text.splitlines():
        if "v0.5.4 strict:" in line:
            m = re.search(r"(\d+)/10 = ([0-9.]+)", line)
            if m:
                strict = float(m.group(2))
        if "v0.5.4 lenient:" in line:
            m = re.search(r"(\d+)/10 = ([0-9.]+)", line)
            if m:
                lenient = float(m.group(2))
    return {
        "strict_recall": strict,
        "lenient_recall": lenient,
        "raw_tail": text.splitlines()[-8:],
    }


def _run_dart_deterministic_sample() -> dict:
    proc = subprocess.run(
        [sys.executable, "scripts/measure_accuracy.py", "--variant", "realistic"],
        cwd=str(DART),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        return {"error": proc.stderr[-300:]}
    text = proc.stdout or ""
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return {"error": "no JSON in measure_accuracy output", "raw": text[-200:]}
    return json.loads(text[start : end + 1])


def _markdown(rows: list[dict], *, model: str, cfreds: dict, det: dict) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    req = [r["required_recall"] for r in rows if "required_recall" in r]
    mean_req = sum(req) / len(req) if req else 0.0
    lines = [
        "# Agentic-DART — live LLM benchmark (cold-box scorer)",
        "",
        f"_Generated: {ts}_",
        "",
        "Private reference under `dont-commit-main-plan/` (not committed).",
        "DART runs via `dart_agent.live`; scored with **cold-box** ground-truth JSON",
        "and keyword matcher (same as `postmortem_agent.scoring`).",
        "",
        "## DART-native benchmarks (deterministic, not live LLM)",
        "",
        f"| Benchmark | Result |",
        f"|-----------|--------|",
        f"| CFReDS strict (measure_cfreds.py) | **{cfreds.get('strict_recall', '?')}** (5/10 v0.5.4 parsers) |",
        f"| CFReDS lenient | {cfreds.get('lenient_recall', '?')} (8/10) |",
        f"| Sample evidence deterministic (F-001+F-013) | recall **{det.get('recall', '?')}** |",
        "",
        "## Live LLM configuration",
        "",
        f"| Setting | Value |",
        f"|---------|-------|",
        f"| Model | `{model}` |",
        f"| Agent | Agentic-DART `dart_agent.live` |",
        f"| Output | `{OUT_ROOT}` |",
        f"| Cases | {len(rows)} |",
        "",
        "## Summary vs cold-box LLM (same GT scorer)",
        "",
        f"| Metric | DART live | cold-box LLM (see LLM-ACCURACY-REPORT.md) |",
        f"|--------|----------:|----------------------------------------------:|",
        f"| Mean required recall | **{mean_req:.3f}** | 0.924 |",
        "",
        "## Per-case (DART live + cold-box GT)",
        "",
        "| Case | Required recall | Recall | Precision | Tool calls | Missed (required) |",
        "|------|----------------:|-------:|----------:|-----------:|-------------------|",
    ]
    for r in rows:
        missed = ", ".join(r.get("missed") or []) or "—"
        lines.append(
            f"| `{r['case_id']}` | {r['required_recall']:.2f} | {r['recall']:.2f} | "
            f"{r['precision']:.2f} | {r.get('tool_calls', '?')} | {missed} |"
        )
    lines.extend([
        "",
        "## Notes",
        "",
        "- DART has **no Android/macOS MCP tools** for Tier-3 cases — expect low scores there unless transcript keywords accidentally match.",
        "- DART live findings are keyword-matched from transcript (generous, same as prior head-to-head doc).",
        "- cold-box **policy** brain still leads on required recall because of deterministic coverage + verifier gate.",
        "- cold-box **hybrid** (`--hybrid`) would combine policy floor + LLM ordering — not run here.",
        "",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--only", help="Comma-separated base case ids")
    ap.add_argument(
        "--out-md",
        default=str(REPO / "dont-commit-main-plan" / "DART-LLM-ACCURACY-REPORT.md"),
    )
    ap.add_argument(
        "--out-json",
        default=str(REPO / "dont-commit-main-plan" / "DART-LLM-ACCURACY-REPORT.json"),
    )
    args = ap.parse_args(argv)

    env = _load_repo_env(dict(os.environ))
    model = env.get("DART_MODEL") or env.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    only = set(args.only.split(",")) if args.only else None

    cfreds = _run_dart_cfreds()
    det = _run_dart_deterministic_sample()

    rows: list[dict] = []
    failures: list[dict] = []

    for entry in manifest:
        base = entry["case_id"].removesuffix("-llm")
        if only and base not in only:
            continue
        if base not in CASE_EVIDENCE:
            continue
        ev_root, ev_sub = CASE_EVIDENCE[base]
        # DART_EVIDENCE_ROOT must point at the case directory itself
        evidence_root = str(Path(ev_root) / ev_sub) if ev_sub != "." else ev_root
        gt_path = REPO / entry["ground_truth"]
        max_iter = entry.get("max_iterations", 16)

        if not args.score_only:
            print(f"[DART RUN] {base} ...", flush=True)
            ok, msg, out_dir = _run_dart_live(
                case_id=base,
                evidence_root=evidence_root,
                max_iterations=max_iter,
                model=model,
                env=env,
            )
            if not ok:
                failures.append({"case_id": base, "error": msg})
                rows.append(
                    {
                        "case_id": base,
                        "required_recall": 0.0,
                        "recall": 0.0,
                        "precision": 0.0,
                        "missed": ["RUN_FAILED"],
                        "tool_calls": 0,
                    }
                )
                continue
        else:
            out_dir = OUT_ROOT / f"{base}-dart-live"

        findings = _parse_report_findings(out_dir)
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        report: ScoreReport = score_findings(
            findings,
            gt,
            self_corrected=_self_corrected(out_dir),
            confirmed_only=True,
        )
        tool_calls = 0
        summary = out_dir / "live_summary.json"
        if summary.is_file():
            tool_calls = int(json.loads(summary.read_text()).get("tool_call_count") or 0)
        row = {
            "case_id": base,
            "required_recall": report.required_recall,
            "recall": report.recall,
            "precision": report.precision,
            "matched": len(report.matched),
            "missed": report.missed,
            "findings": report.finding_count,
            "tool_calls": tool_calls,
            "output_dir": str(out_dir),
        }
        rows.append(row)
        print(
            f"[{base}] required_recall={row['required_recall']:.2f} "
            f"recall={row['recall']:.2f} tool_calls={tool_calls}",
            flush=True,
        )

    md = _markdown(rows, model=model, cfreds=cfreds, det=det)
    Path(args.out_md).write_text(md, encoding="utf-8")
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "agent": "agentic-dart-live",
        "model": model,
        "mean_required_recall": round(
            sum(r["required_recall"] for r in rows) / max(1, len(rows)), 3
        ),
        "cfreds": cfreds,
        "deterministic_sample": det,
        "cases": rows,
        "failures": failures,
    }
    Path(args.out_json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {args.out_md}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
