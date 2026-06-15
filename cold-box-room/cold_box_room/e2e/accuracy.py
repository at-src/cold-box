"""Score hallway E2E output against community ground-truth benchmarks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cold_box_room.e2e.report import collect_case_report
from cold_box_room.r1.evidence import staging_names_from_manifest, validate_benchmark_staging_scope
from cold_box_room.r1.paths import case_records_dir
from cold_box_room.r2.audit import audit_log_path

BENCHMARKS_DIR = Path(__file__).resolve().parent / "benchmarks"


def list_benchmarks() -> list[str]:
    return sorted(p.stem for p in BENCHMARKS_DIR.glob("*.json"))


def load_benchmark(benchmark_id: str) -> dict[str, Any]:
    path = BENCHMARKS_DIR / f"{benchmark_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"Unknown benchmark {benchmark_id!r} — have: {list_benchmarks()}")
    return json.loads(path.read_text(encoding="utf-8"))


def _collect_corpus(case_id: str, report: dict[str, Any]) -> str:
    chunks: list[str] = []
    for layer in ("layer1", "layer2"):
        block = report.get(layer) or {}
        for key in ("findings", "why", "corrections"):
            val = block.get(key)
            if val:
                chunks.append(str(val))
        parsed = (block.get("analyst_log") or {}).get("parsed") or {}
        for key in ("findings", "why", "corrections", "raw"):
            val = parsed.get(key)
            if val:
                chunks.append(str(val))
    plans = report.get("plans") or {}
    for key in ("plan_a_excerpt", "plan_b_excerpt"):
        val = plans.get(key)
        if val:
            chunks.append(str(val))

    records = case_records_dir(case_id)
    for name in ("plan_a.md", "plan_b.md", "layer1_analyst_log.md", "layer2_analyst_log.md"):
        path = records / name
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))

    audit = audit_log_path(case_id)
    if audit.is_file():
        for line in audit.read_text(encoding="utf-8", errors="replace").splitlines()[-400:]:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            chunks.append(str(row.get("stdout_preview") or ""))
            chunks.append(str(row.get("purpose") or ""))
            chunks.append(str(row.get("why") or ""))

    return "\n".join(chunks).lower()


def _audit_tool_stats(case_id: str, tool_name: str) -> dict[str, int]:
    path = audit_log_path(case_id)
    if not path.is_file():
        return {"runs": 0, "cached": 0, "success": 0}
    runs = cached = success = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("tool_name") != tool_name:
            continue
        runs += 1
        cmd = row.get("command") or []
        if any("(cached)" in str(part) for part in cmd):
            cached += 1
        if int(row.get("exit_code") or 1) == 0:
            success += 1
    return {"runs": runs, "cached": cached, "success": success}


def _pct(num: float) -> float:
    return round(100.0 * num, 1)


def _classification_metrics(*, tp: int, fn: int, fp: int = 0) -> dict[str, Any]:
    total = tp + fn
    recall = tp / total if total else 1.0
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if fn == 0 else 0.0)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "total": total,
        "recall": round(recall, 4),
        "recall_pct": _pct(recall),
        "precision": round(precision, 4),
        "precision_pct": _pct(precision),
        "f1": round(f1, 4),
        "f1_pct": _pct(f1),
    }


def _agent_usage_stats(case_id: str) -> dict[str, Any]:
    path = case_records_dir(case_id) / "AGENT_RUN.jsonl"
    if not path.is_file():
        return {}
    turns = cache_read = cache_create = input_tok = output_tok = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("type") != "assistant":
            continue
        turns += 1
        usage = row.get("usage") or {}
        cache_read += int(usage.get("cache_read_input_tokens") or 0)
        cache_create += int(usage.get("cache_creation_input_tokens") or 0)
        input_tok += int(usage.get("input_tokens") or 0)
        output_tok += int(usage.get("output_tokens") or 0)
    return {
        "assistant_turns": turns,
        "input_tokens": input_tok,
        "output_tokens": output_tok,
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_create,
    }


def _load_staging_manifest(case_id: str) -> dict[str, Any]:
    path = case_records_dir(case_id) / "manifest.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def score_case_accuracy(
    *,
    case_id: str,
    benchmark_id: str,
    run_id: str = "",
    hallway_status: str = "",
    wall_clock_seconds: float | None = None,
    started_at: str = "",
    finished_at: str = "",
) -> dict[str, Any]:
    benchmark = load_benchmark(benchmark_id)
    report = collect_case_report(case_id)
    corpus = _collect_corpus(case_id, report)
    manifest = _load_staging_manifest(case_id)
    staged_files = staging_names_from_manifest(manifest)
    staging_scope = validate_benchmark_staging_scope(staged_files=staged_files, benchmark=benchmark)

    checks_out: list[dict[str, Any]] = []
    required_hits = required_total = optional_hits = optional_total = 0
    skipped_checks = 0

    for check in benchmark.get("checks") or []:
        requires_files = [str(name) for name in check.get("requires_staging_files") or [] if str(name).strip()]
        if requires_files and not all(name in staged_files for name in requires_files):
            skipped_checks += 1
            checks_out.append(
                {
                    "id": check.get("id", ""),
                    "label": check.get("label", ""),
                    "patterns": check.get("patterns") or [],
                    "required": bool(check.get("required", True)),
                    "hit": False,
                    "skipped": True,
                    "skip_reason": f"requires staging files: {', '.join(requires_files)}",
                }
            )
            continue

        patterns = [str(p).lower() for p in check.get("patterns") or [] if str(p).strip()]
        hit = any(p in corpus for p in patterns) if patterns else False
        if not hit and patterns:
            # allow simple word-boundary regex for short tokens
            for p in patterns:
                if len(p) >= 4 and re.search(re.escape(p), corpus):
                    hit = True
                    break
        required = bool(check.get("required", True))
        if required:
            required_total += 1
            if hit:
                required_hits += 1
        else:
            optional_total += 1
            if hit:
                optional_hits += 1
        checks_out.append(
            {
                "id": check.get("id", ""),
                "label": check.get("label", ""),
                "patterns": check.get("patterns") or [],
                "required": required,
                "hit": hit,
            }
        )

    ewf = _audit_tool_stats(case_id, "ewfverify")
    layer1_score = ((report.get("layer1") or {}).get("self_score"))
    layer2_score = ((report.get("layer2") or {}).get("self_score"))
    usage = _agent_usage_stats(case_id)

    req = _classification_metrics(tp=required_hits, fn=required_total - required_hits)
    opt = _classification_metrics(tp=optional_hits, fn=optional_total - optional_hits)
    all_tp = required_hits + optional_hits
    all_fn = (required_total - required_hits) + (optional_total - optional_hits)
    all_metrics = _classification_metrics(tp=all_tp, fn=all_fn)

    payload: dict[str, Any] = {
        "schema": "cold_box_room.accuracy_score_v1",
        "run_id": run_id or case_id,
        "case_id": case_id,
        "benchmark_id": benchmark_id,
        "benchmark_title": benchmark.get("title", benchmark_id),
        "evidence": benchmark.get("evidence_path") or benchmark.get("evidence_paths"),
        "staging_scope": staging_scope,
        "staging_scope_ok": staging_scope.get("scope_ok"),
        "hallway_status": hallway_status or report.get("room"),
        "complete": bool(report.get("complete")),
        "room": report.get("room"),
        "required_recall": f"{required_hits}/{required_total}",
        "required_recall_pct": req["recall_pct"],
        "optional_recall": f"{optional_hits}/{optional_total}",
        "optional_recall_pct": opt["recall_pct"],
        "metrics": {
            "required": req,
            "optional": opt,
            "all": all_metrics,
        },
        "accuracy_pct": all_metrics["recall_pct"] if staging_scope.get("scope_ok") else None,
        "accuracy_scoped": staging_scope.get("scope_ok"),
        "checks_skipped": skipped_checks,
        "checks": checks_out,
        "ewfverify_runs": ewf["runs"],
        "ewfverify_cached": ewf["cached"],
        "ewfverify_success": ewf["success"],
        "layer1_self_score": layer1_score,
        "layer2_self_score": layer2_score,
        "prompt_cache_enabled": __import__("os").environ.get("ANTHROPIC_PROMPT_CACHE", "1"),
        "usage": usage,
    }
    if wall_clock_seconds is not None:
        payload["timing"] = {
            "started_at": started_at,
            "finished_at": finished_at,
            "wall_clock_seconds": round(float(wall_clock_seconds), 1),
            "wall_clock_minutes": round(float(wall_clock_seconds) / 60.0, 2),
        }
    return payload


def write_accuracy_report(payload: dict[str, Any], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path
