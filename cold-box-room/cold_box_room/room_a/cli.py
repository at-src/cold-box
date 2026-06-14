"""CLI — formalize plan_a.md into plan_a.py."""

from __future__ import annotations

import argparse
import json
import sys

from cold_box_room.planning.formalize import FormalizePlanError, formalize_plan
from cold_box_room.room_a import room_a_checkpoint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Formalize plan_a.md → plan_a.py")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--status", action="store_true", help="Print room A checkpoint after formalize")
    args = parser.parse_args(argv)

    try:
        result = formalize_plan(case_id=args.case_id, room="a")
    except FormalizePlanError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    if args.status:
        print(json.dumps(room_a_checkpoint(args.case_id), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
