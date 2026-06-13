"""CLI — Room 1 staging table."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cold_box_room.r1.checkpoint import r1_checkpoint
from cold_box_room.r1.hallway import current_room, promote_to_room2, record_r1_check
from cold_box_room.r1.intake import intake_case, list_table_cases
from cold_box_room.r1.paths import get_records_root, get_table_root, hallway_state_path
from cold_box_room.r1.seal import is_sealed, seal_record_path
from cold_box_room.r1.viewport import open_viewport


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="cold-box-room R1 — raw evidence on table, glass sealed",
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
        help="Promote to room 2 when checkpoint passes",
    )

    p_intake = sub.add_parser("intake")
    p_intake.add_argument("--case-id", required=True)
    p_intake.add_argument("--source", default="")
    p_intake.add_argument("--link", action="store_true")

    p_peek = sub.add_parser("viewport-ls")
    p_peek.add_argument("--case-id", required=True)
    p_peek.add_argument("--path", default=".")

    args = parser.parse_args(argv)

    if args.command == "paths":
        print(
            json.dumps(
                {
                    "operation_table": str(get_table_root()),
                    "records": str(get_records_root()),
                    "machine_channel": "cold_box_room.r1.viewport.open_viewport",
                },
                indent=2,
            )
        )
        return 0

    if args.command == "list":
        print(json.dumps({"cases_on_table": list_table_cases()}, indent=2))
        return 0

    if args.command == "r1-status":
        sealed = is_sealed(args.case_id)
        out: dict = {
            "case_id": args.case_id,
            "room": current_room(args.case_id) if hallway_state_path(args.case_id).is_file() else None,
            "sealed": sealed,
            "glass": "locked" if sealed else "open",
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
            promoted = promote_to_room2(args.case_id)
            print(json.dumps({"checkpoint": check, "hallway": promoted}, indent=2))
        else:
            print(json.dumps(check, indent=2))
        return 0 if check["ok"] else 2

    if args.command == "intake":
        src = Path(args.source).expanduser() if args.source else None
        print(json.dumps(intake_case(args.case_id, source=src, link_only=args.link), indent=2))
        return 0

    if args.command == "viewport-ls":
        vp = open_viewport(args.case_id)
        entries = [
            {"relpath": e.relpath, "is_dir": e.is_dir, "size": e.size}
            for e in vp.list_dir(args.path)
        ]
        print(json.dumps({"channel": vp.CHANNEL, "entries": entries}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
