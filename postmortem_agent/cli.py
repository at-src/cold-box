"""CLI for cold-box investigation agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from postmortem_agent.core import run_investigation
from postmortem_agent.state import AgentConfig
from postmortem_audit import verify_chain
from postmortem_mcp.config import audit_log_path, case_dir


def _parse_mode(args: argparse.Namespace) -> str:
    if args.synthetic:
        return "synthetic"
    if args.llm:
        return "llm"
    return "autonomous"


def cmd_run(args: argparse.Namespace) -> int:
    mode = _parse_mode(args)
    fixture_dir = Path(args.fixture_dir) if args.fixture_dir else None
    cache_dir = Path(args.from_cache).expanduser() if args.from_cache else None
    extracted = Path(args.extracted_root).expanduser() if args.extracted_root else None
    artifact_root = Path(args.artifact_root).expanduser() if args.artifact_root else None

    config = AgentConfig(
        case_id=args.case_id,
        evidence_case=args.evidence_case,
        memory_relpath=args.memory,
        prefetch_relpath=args.prefetch,
        amcache_relpath=args.amcache,
        mft_relpath=args.mft,
        evtx_relpath=args.evtx,
        mode=mode,  # type: ignore[arg-type]
        max_iterations=args.max_iterations,
        fixture_dir=fixture_dir,
        cache_dir=cache_dir,
        artifact_root=artifact_root,
        extracted_root=extracted,
        llm_model=args.llm_model,
        search_patterns=args.search_patterns.split(",") if args.search_patterns else None,
    )
    state = run_investigation(config)

    out_dir = case_dir(config.case_id)
    audit_ok, audit_msg = verify_chain(audit_log_path(config.case_id))
    summary = {
        "case_id": config.case_id,
        "mode": config.mode,
        "done": state.done,
        "phase": state.phase,
        "hypothesis": state.hypothesis,
        "confidence": state.confidence,
        "self_corrected": state.self_corrected,
        "iterations": state.iteration,
        "lessons_count": len(state.lessons),
        "findings_count": len(state.findings),
        "kinds_present": state.survey.get("kinds_present"),
        "audit_chain_ok": audit_ok,
        "audit_chain_message": audit_msg,
        "output_dir": str(out_dir),
        "report_md": str(out_dir / "report.md"),
        "report_json": str(out_dir / "report.json"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    if not audit_ok:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cold-box autonomous investigation agent")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run autonomous investigation")
    p_run.add_argument("--case-id", required=True, help="Output case id under CASE_OUTPUT")
    p_run.add_argument(
        "--evidence-case",
        required=True,
        help="Case directory path relative to EVIDENCE_ROOT",
    )
    p_run.add_argument("--memory", help="Optional memory relpath hint (agent may override via survey)")
    p_run.add_argument("--prefetch", help="Optional prefetch relpath hint")
    p_run.add_argument("--amcache", help="Optional amcache relpath hint")
    p_run.add_argument("--mft", help="Optional MFT relpath hint")
    p_run.add_argument("--evtx", help="Optional EVTX relpath hint")
    p_run.add_argument(
        "--llm",
        action="store_true",
        help="Use LLM reasoner (requires ANTHROPIC_API_KEY)",
    )
    p_run.add_argument(
        "--synthetic",
        action="store_true",
        help="Use bundled fixtures for memory tools (CI/regression)",
    )
    p_run.add_argument(
        "--from-cache",
        help="Directory with cached mem_*.json for fast replay on real cases",
    )
    p_run.add_argument("--artifact-root", help="Writable case root with cache/")
    p_run.add_argument("--extracted-root", help="Extracted disk artifacts root for verifier index")
    p_run.add_argument(
        "--fixture-dir",
        help="Fixture directory (default: examples/sample-verifier with --synthetic)",
    )
    p_run.add_argument("--search-patterns", help="Comma-separated IOC patterns for search tool")
    p_run.add_argument("--llm-model", help="Anthropic model id for --llm")
    p_run.add_argument("--max-iterations", type=int, default=25)
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
