#!/usr/bin/env python3
"""Run cold-box-room Layer 1 agent (R2) with Anthropic tool use."""

from __future__ import annotations

import argparse
import json
import sys

from cold_box_room.agent.engine import run_layer1_agent
from cold_box_room.agent.reset import reset_layer1_agent_state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Layer 1 agent on a case in room 2")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--goal", required=True)
    parser.add_argument("--max-turns", type=int, default=45)
    parser.add_argument("--model", default="")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear scratch, tool logs, and AGENT_RUN before starting",
    )
    args = parser.parse_args(argv)

    if args.reset:
        removed = reset_layer1_agent_state(args.case_id)
        print(json.dumps({"reset": removed}, indent=2))

    result = run_layer1_agent(
        case_id=args.case_id,
        goal=args.goal,
        max_turns=args.max_turns,
        model=args.model or None,
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("promoted_to_room_b") else 1


if __name__ == "__main__":
    sys.exit(main())
