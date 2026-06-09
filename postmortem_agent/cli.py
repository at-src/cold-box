"""CLI for cold-box investigation agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from postmortem_agent.loop import run_investigation
from postmortem_agent.state import AgentConfig
from postmortem_audit import verify_chain
from postmortem_mcp.config import audit_log_path, case_dir


def cmd_run(args: argparse.Namespace) -> int:
    mode = "synthetic" if args.synthetic else "live"
    fixture_dir = Path(args.fixture_dir) if args.fixture_dir else None
    config = AgentConfig(
        case_id=args.case_id,
        evidence_case=args.evidence_case,
        memory_relpath=args.memory,
        mode=mode,
        max_iterations=args.max_iterations,
        fixture_dir=fixture_dir,
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
        "findings_count": len(state.findings),
        "audit_chain_ok": audit_ok,
        "audit_chain_message": audit_msg,
        "output_dir": str(out_dir),
        "report_md": str(out_dir / "report.md"),
        "report_json": str(out_dir / "report.json"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    if not audit_ok:
        return 1
    if state.unresolved and not state.self_corrected:
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cold-box investigation agent")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run scripted investigation loop")
    p_run.add_argument("--case-id", required=True, help="Output case id under CASE_OUTPUT")
    p_run.add_argument(
        "--evidence-case",
        required=True,
        help="Case directory path relative to EVIDENCE_ROOT",
    )
    p_run.add_argument(
        "--memory",
        help="Memory image path relative to EVIDENCE_ROOT (required for live mode)",
    )
    p_run.add_argument(
        "--synthetic",
        action="store_true",
        help="Use bundled fixtures (fast demo; R1 self-correction path)",
    )
    p_run.add_argument(
        "--fixture-dir",
        help="Fixture directory for synthetic mode (default: examples/sample-verifier)",
    )
    p_run.add_argument("--max-iterations", type=int, default=10)
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
