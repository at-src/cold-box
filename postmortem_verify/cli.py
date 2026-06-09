"""CLI for cold-box verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from postmortem_verify.engine import run_r1, run_verifier
from postmortem_verify.models import VerifyContext


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _tool_data_from_file(path: Path) -> tuple[dict[str, Any], str | None]:
    payload = _load_json(path)
    if "data" in payload and isinstance(payload["data"], dict):
        return payload["data"], payload.get("audit_id")
    return payload, payload.get("audit_id")


def cmd_r1(args: argparse.Namespace) -> int:
    pslist_data, pslist_audit = _tool_data_from_file(Path(args.pslist))
    psscan_data, psscan_audit = _tool_data_from_file(Path(args.psscan))
    ctx = VerifyContext.from_tool_payloads(
        pslist_data=pslist_data,
        psscan_data=psscan_data,
        pslist_audit_id=pslist_audit,
        psscan_audit_id=psscan_audit,
    )
    result = run_r1(ctx)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status != "contradiction" else 2


def cmd_run(args: argparse.Namespace) -> int:
    pslist_data, pslist_audit = _tool_data_from_file(Path(args.pslist))
    psscan_data, psscan_audit = _tool_data_from_file(Path(args.psscan))
    ctx = VerifyContext.from_tool_payloads(
        pslist_data=pslist_data,
        psscan_data=psscan_data,
        pslist_audit_id=pslist_audit,
        psscan_audit_id=psscan_audit,
    )
    results = run_verifier(ctx)
    payload = {"results": [result.to_dict() for result in results]}
    print(json.dumps(payload, indent=2, sort_keys=True))
    contradictions = sum(1 for result in results if result.status == "contradiction")
    return 2 if contradictions else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cold-box deterministic verifier")
    sub = parser.add_subparsers(dest="command", required=True)

    p_r1 = sub.add_parser("r1", help="Run R1 hidden_process rule")
    p_r1.add_argument("--pslist", required=True, help="JSON from mem_pslist tool output")
    p_r1.add_argument("--psscan", required=True, help="JSON from mem_psscan tool output")
    p_r1.set_defaults(func=cmd_r1)

    p_run = sub.add_parser("run", help="Run all implemented verifier rules")
    p_run.add_argument("--pslist", required=True)
    p_run.add_argument("--psscan", required=True)
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
