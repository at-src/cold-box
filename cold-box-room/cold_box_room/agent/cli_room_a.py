#!/usr/bin/env python3
"""Run cold-box-room Room A agent (extraction planning) with Anthropic tool use."""

from __future__ import annotations

import argparse
import json
import sys

from cold_box_room.agent.engine import run_room_a_agent
from cold_box_room.agent.prompts import DEFAULT_ROOM_A_GOAL


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Room A extraction planning agent")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--goal", default=DEFAULT_ROOM_A_GOAL)
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--model", default="")
    args = parser.parse_args(argv)

    result = run_room_a_agent(
        case_id=args.case_id,
        goal=args.goal,
        max_turns=args.max_turns,
        model=args.model or None,
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("ready_for_room2") else 1


if __name__ == "__main__":
    sys.exit(main())
