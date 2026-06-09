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


def _build_context(args: argparse.Namespace) -> VerifyContext:
    pslist_data, pslist_audit = _tool_data_from_file(Path(args.pslist))
    psscan_data, psscan_audit = _tool_data_from_file(Path(args.psscan))

    amcache_data = amcache_audit = None
    if args.amcache:
        amcache_data, amcache_audit = _tool_data_from_file(Path(args.amcache))

    prefetch_data = prefetch_audit = None
    if args.prefetch:
        prefetch_data, prefetch_audit = _tool_data_from_file(Path(args.prefetch))

    mft_data = mft_audit = None
    if args.mft:
        mft_data, mft_audit = _tool_data_from_file(Path(args.mft))

    timestomp_data = None
    if args.timestomp:
        timestomp_data, timestomp_audit = _tool_data_from_file(Path(args.timestomp))
        mft_audit = mft_audit or timestomp_audit

    netscan_data = netscan_audit = None
    if args.netscan:
        netscan_data, netscan_audit = _tool_data_from_file(Path(args.netscan))

    return VerifyContext.from_tool_payloads(
        pslist_data=pslist_data,
        psscan_data=psscan_data,
        amcache_data=amcache_data,
        prefetch_data=prefetch_data,
        mft_data=mft_data,
        timestomp_data=timestomp_data,
        netscan_data=netscan_data,
        evidence_root=args.evidence_root,
        pslist_audit_id=pslist_audit,
        psscan_audit_id=psscan_audit,
        amcache_audit_id=amcache_audit,
        prefetch_audit_id=prefetch_audit,
        mft_audit_id=mft_audit,
        netscan_audit_id=netscan_audit,
        timestomp_tolerance_seconds=args.tolerance_seconds,
    )


def cmd_r1(args: argparse.Namespace) -> int:
    ctx = _build_context(args)
    result = run_r1(ctx)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status != "contradiction" else 2


def cmd_run(args: argparse.Namespace) -> int:
    ctx = _build_context(args)
    results = run_verifier(ctx)
    payload = {"results": [result.to_dict() for result in results]}
    print(json.dumps(payload, indent=2, sort_keys=True))
    contradictions = sum(1 for result in results if result.status == "contradiction")
    return 2 if contradictions else 0


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pslist", required=True, help="JSON from mem_pslist tool output")
    parser.add_argument("--psscan", required=True, help="JSON from mem_psscan tool output")
    parser.add_argument("--amcache", help="JSON from disk_parse_amcache")
    parser.add_argument("--prefetch", help="JSON from disk_parse_prefetch")
    parser.add_argument("--mft", help="JSON from disk_parse_mft")
    parser.add_argument("--timestomp", help="JSON from disk_detect_timestomp")
    parser.add_argument("--netscan", help="JSON from mem_netscan")
    parser.add_argument(
        "--evidence-root",
        help="Evidence directory for R5 ghost_binary file existence checks",
    )
    parser.add_argument("--tolerance-seconds", type=int, default=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cold-box deterministic verifier")
    sub = parser.add_subparsers(dest="command", required=True)

    p_r1 = sub.add_parser("r1", help="Run R1 hidden_process rule")
    _add_common_args(p_r1)
    p_r1.set_defaults(func=cmd_r1)

    p_run = sub.add_parser("run", help="Run all implemented verifier rules")
    _add_common_args(p_run)
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
