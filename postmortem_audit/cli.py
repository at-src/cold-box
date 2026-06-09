"""CLI for cold-box audit logs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from postmortem_audit.log import iter_entries, verify_chain


def cmd_verify(args: argparse.Namespace) -> int:
    ok, message = verify_chain(args.path)
    print(message)
    return 0 if ok else 1


def cmd_lookup(args: argparse.Namespace) -> int:
    for entry in iter_entries(args.path):
        if entry.get("audit_id") == args.audit_id:
            print(json.dumps(entry, indent=2, sort_keys=True))
            return 0
    print(f"error: audit_id not found: {args.audit_id}", file=sys.stderr)
    return 2


def cmd_summary(args: argparse.Namespace) -> int:
    entries = list(iter_entries(args.path))
    by_tool: dict[str, int] = {}
    by_iteration: dict[int, int] = {}
    for entry in entries:
        tool = entry.get("tool", "?")
        by_tool[tool] = by_tool.get(tool, 0) + 1
        iteration = int(entry.get("iteration", 0))
        by_iteration[iteration] = by_iteration.get(iteration, 0) + 1

    ok, verify_message = verify_chain(args.path)
    summary = {
        "path": str(Path(args.path).resolve()),
        "entry_count": len(entries),
        "chain_verified": ok,
        "chain_message": verify_message,
        "by_tool": by_tool,
        "by_iteration": {str(k): v for k, v in sorted(by_iteration.items())},
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cold-box audit log tools")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="Verify audit.jsonl hash chain")
    p_verify.add_argument("path", help="Path to audit.jsonl")
    p_verify.set_defaults(func=cmd_verify)

    p_lookup = sub.add_parser("lookup", help="Fetch one entry by audit_id")
    p_lookup.add_argument("path", help="Path to audit.jsonl")
    p_lookup.add_argument("audit_id", help="8-char audit_id hex")
    p_lookup.set_defaults(func=cmd_lookup)

    p_summary = sub.add_parser("summary", help="Summarize audit.jsonl")
    p_summary.add_argument("path", help="Path to audit.jsonl")
    p_summary.set_defaults(func=cmd_summary)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
