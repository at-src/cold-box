#!/usr/bin/env python3
"""CLI — Room 3 Layer 2 agent run."""

from __future__ import annotations

import argparse

from cold_box_room.agent.engine import run_room3_agent
from cold_box_room.agent.prompts import DEFAULT_ROOM_3_GOAL


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Room 3 Layer 2 analysis agent")
    parser.add_argument("case_id")
    parser.add_argument("--goal", default=DEFAULT_ROOM_3_GOAL)
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument("--model", default="")
    args = parser.parse_args()

    result = run_room3_agent(
        case_id=args.case_id,
        goal=args.goal,
        max_turns=args.max_turns,
        model=args.model or None,
    )
    print(result)
    return 0 if result.get("layer2_complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
