"""CLI — cold-box hallway rooms."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cold_box_room.r1.checkpoint import r1_checkpoint
from cold_box_room.r1.hallway import current_room, promote_to_room_a, promote_to_room2, record_r1_check
from cold_box_room.r1.intake import intake_case, list_staging_cases
from cold_box_room.r1.paths import get_records_root, get_staging_root, hallway_state_path
from cold_box_room.r1.seal import is_sealed, seal_record_path
from cold_box_room.r1.staging_read import open_staging_read
from cold_box_room.r2.checkpoint import r2_layer1_checkpoint, submit_layer1_writeup
from cold_box_room.r2.paths import case_sandbox_dir, get_sandbox_root
from cold_box_room.r2.sandbox import list_sandbox_files, r2_status
from cold_box_room.r2.analyst_log import read_analyst_log
from cold_box_room.r2.tool_log import read_tool_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="cold-box-room — deterministic hallway rooms",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("paths")
    sub.add_parser("list")

    p_status = sub.add_parser("r1-status")
    p_status.add_argument("--case-id", required=True)

    p_check = sub.add_parser("r1-check")
    p_check.add_argument("--case-id", required=True)
    p_check.add_argument(
        "--promote",
        action="store_true",
        help="Promote to Room A when checkpoint passes (Room 2 requires Room A gate)",
    )

    p_intake = sub.add_parser("intake")
    p_intake.add_argument("--case-id", required=True)
    p_intake.add_argument("--source", default="")
    p_intake.add_argument("--link", action="store_true")

    p_ls = sub.add_parser("staging-ls")
    p_ls.add_argument("--case-id", required=True)
    p_ls.add_argument("--path", default=".")

    p_r2 = sub.add_parser("r2-status")
    p_r2.add_argument("--case-id", required=True)

    p_sandbox_ls = sub.add_parser("sandbox-ls")
    p_sandbox_ls.add_argument("--case-id", required=True)

    p_layer1 = sub.add_parser("layer1-status")
    p_layer1.add_argument("--case-id", required=True)

    p_r2check = sub.add_parser("r2-check")
    p_r2check.add_argument("--case-id", required=True)
    p_r2check.add_argument("--findings", default="")
    p_r2check.add_argument("--self-score", type=int, default=0)
    p_r2check.add_argument("--why", default="")
    p_r2check.add_argument(
        "--submit",
        action="store_true",
        help="Submit Layer 1 analyst write-up (requires findings, self-score, why)",
    )

    args = parser.parse_args(argv)

    if args.command == "paths":
        print(
            json.dumps(
                {
                    "r1_staging_root": str(get_staging_root()),
                    "r2_sandbox_root": str(get_sandbox_root()),
                    "records_root": str(get_records_root()),
                    "read_channel": "cold_box_room.r1.staging_read.open_staging_read",
                },
                indent=2,
            )
        )
        return 0

    if args.command == "list":
        print(json.dumps({"cases_in_r1_staging": list_staging_cases()}, indent=2))
        return 0

    if args.command == "r1-status":
        sealed = is_sealed(args.case_id)
        out: dict = {
            "case_id": args.case_id,
            "room": current_room(args.case_id) if hallway_state_path(args.case_id).is_file() else None,
            "sealed": sealed,
        }
        if sealed:
            out["r1_checkpoint"] = r1_checkpoint(args.case_id)
            if seal_record_path(args.case_id).is_file():
                out["seal"] = json.loads(seal_record_path(args.case_id).read_text())
        print(json.dumps(out, indent=2))
        return 0

    if args.command == "r1-check":
        check = record_r1_check(args.case_id)
        if args.promote and check["ok"]:
            promoted = promote_to_room_a(args.case_id)
            print(json.dumps({"checkpoint": check, "hallway": promoted}, indent=2))
        else:
            print(json.dumps(check, indent=2))
        return 0 if check["ok"] else 2

    if args.command == "intake":
        src = Path(args.source).expanduser() if args.source else None
        print(json.dumps(intake_case(args.case_id, source=src, link_only=args.link), indent=2))
        return 0

    if args.command == "staging-ls":
        reader = open_staging_read(args.case_id)
        entries = [
            {"relpath": e.relpath, "is_dir": e.is_dir, "size": e.size}
            for e in reader.list_dir(args.path)
        ]
        print(json.dumps({"channel": reader.CHANNEL, "entries": entries}, indent=2))
        return 0

    if args.command == "r2-status":
        print(json.dumps(r2_status(args.case_id), indent=2))
        return 0

    if args.command == "sandbox-ls":
        files = list_sandbox_files(args.case_id)
        print(
            json.dumps(
                {
                    "case_id": args.case_id,
                    "sandbox_dir": str(case_sandbox_dir(args.case_id)),
                    "files": files,
                },
                indent=2,
            )
        )
        return 0

    if args.command == "layer1-status":
        print(
            json.dumps(
                {
                    "checkpoint": r2_layer1_checkpoint(args.case_id),
                    "tool_log": read_tool_log(args.case_id),
                    "analyst_log": read_analyst_log(args.case_id),
                },
                indent=2,
            )
        )
        return 0

    if args.command == "r2-check":
        if args.submit:
            if not args.findings or not args.why or args.self_score < 1:
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "error": "Use --findings, --self-score, and --why with --submit",
                        },
                        indent=2,
                    )
                )
                return 2
            result = submit_layer1_writeup(
                case_id=args.case_id,
                findings=args.findings,
                self_score=args.self_score,
                why=args.why,
            )
            print(json.dumps(result, indent=2))
            return 0 if result.get("promoted") else 2
        print(json.dumps(r2_layer1_checkpoint(args.case_id), indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
