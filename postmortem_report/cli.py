"""CLI for cold-box report generation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from postmortem_mcp.config import case_dir, validate_case_id
from postmortem_report.gate import FindingGateError, validate_findings
from postmortem_report.report import load_findings, write_report


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.findings)
    try:
        findings = load_findings(path)
    except FindingGateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "finding_count": len(findings)}, indent=2))
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    case_id = validate_case_id(args.case_id)
    out_dir = case_dir(case_id)
    try:
        report = write_report(out_dir, case_id=case_id)
    except (FindingGateError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "ok": True,
                "case_id": case_id,
                "report_md": str(out_dir / "report.md"),
                "report_json": str(out_dir / "report.json"),
                "confirmed": len(report["confirmed"]),
                "unresolved": len(report["unresolved"]),
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cold-box report generator")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="Validate findings.json gate")
    p_validate.add_argument("findings", help="Path to findings.json")
    p_validate.set_defaults(func=cmd_validate)

    p_generate = sub.add_parser("generate", help="Generate report.md and report.json")
    p_generate.add_argument("--case-id", required=True, help="Case id under CASE_OUTPUT")
    p_generate.set_defaults(func=cmd_generate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
