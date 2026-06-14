"""Full hallway E2E — R1 → A → 2 → B → 3 → case report."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cold_box_room.agent.prompts import (
    DEFAULT_LAYER1_GOAL,
    DEFAULT_ROOM_3_GOAL,
    DEFAULT_ROOM_A_GOAL,
    DEFAULT_ROOM_B_GOAL,
)
from cold_box_room.e2e.report import collect_case_report
from cold_box_room.e2e.run_layer1 import (
    DEFAULT_JO_E01,
    bind_workspace,
    deliver_to_room_a,
    prepare_fresh_workspace,
    preflight_agent,
    preflight_room_a,
)
from cold_box_room.r1.hallway import current_room, promote_to_room2, promote_to_room3
from cold_box_room.r1.paths import get_records_root
from cold_box_room.r2.sandbox import list_sandbox_files
from cold_box_room.room_a import fast_pass_room_a, room_a_checkpoint
from cold_box_room.room_b import fast_pass_room_b, room_b_checkpoint


def preflight_room_b(*, case_id: str) -> dict[str, Any]:
    from cold_box_room.agent.llm import anthropic_api_key, load_dotenv, prompt_cache_enabled

    load_dotenv()
    room = current_room(case_id)
    if room != "B":
        raise RuntimeError(f"Case {case_id!r} is room {room}, need room B before Room B agent")
    anthropic_api_key()
    return {"room": room, "prompt_cache": prompt_cache_enabled()}


def preflight_room3(*, case_id: str) -> dict[str, Any]:
    from cold_box_room.agent.llm import anthropic_api_key, load_dotenv, prompt_cache_enabled

    load_dotenv()
    room = current_room(case_id)
    if room != "3":
        raise RuntimeError(f"Case {case_id!r} is room {room}, need room 3 before Room 3 agent")
    files = list_sandbox_files(case_id)
    if not files:
        raise RuntimeError(f"No files in R2 sandbox for {case_id!r}")
    anthropic_api_key()
    return {
        "room": room,
        "sandbox_files": files,
        "prompt_cache": prompt_cache_enabled(),
    }


def run_hallway_e2e(
    *,
    run_id: str,
    case_id: str | None = None,
    evidence_path: Path | None = None,
    room_a_goal: str | None = None,
    layer1_goal: str | None = None,
    room_b_goal: str | None = None,
    room3_goal: str | None = None,
    room_a_max_turns: int = 15,
    layer1_max_turns: int = 45,
    room_b_max_turns: int = 15,
    room3_max_turns: int = 30,
    run_agents: bool = True,
    run_room_a: bool = True,
    run_layer1: bool = True,
    run_room_b: bool = True,
    run_room3: bool = True,
    skip_room_a_agent: bool = False,
    skip_layer1_agent: bool = False,
    skip_room_b_agent: bool = False,
    skip_room3_agent: bool = False,
    model: str | None = None,
    reuse_kitchen: bool = False,
) -> dict[str, Any]:
    """Run the full hallway: intake → four agent rooms → collect report."""
    case_id = case_id or run_id

    if reuse_kitchen:
        paths = bind_workspace(run_id=run_id)
        kitchen = {
            "ok": True,
            "case_id": case_id,
            "room": current_room(case_id),
            "reused": True,
            "sandbox_files": list_sandbox_files(case_id) if current_room(case_id) in {"2", "B", "3"} else [],
        }
    else:
        paths = prepare_fresh_workspace(run_id=run_id, wipe=True)
        kitchen = deliver_to_room_a(case_id=case_id, evidence_path=evidence_path)

    result: dict[str, Any] = {
        "run_id": run_id,
        "case_id": case_id,
        "workspace": paths,
        "kitchen": kitchen,
        "room_a_goal": room_a_goal or DEFAULT_ROOM_A_GOAL,
        "layer1_goal": layer1_goal or DEFAULT_LAYER1_GOAL,
        "room_b_goal": room_b_goal or DEFAULT_ROOM_B_GOAL,
        "room3_goal": room3_goal or DEFAULT_ROOM_3_GOAL,
        "prompt_cache": os.environ.get("ANTHROPIC_PROMPT_CACHE", "1"),
        "room_a_agent": None,
        "layer1_agent": None,
        "room_b_agent": None,
        "room3_agent": None,
        "report": None,
    }

    if not run_agents:
        result["status"] = "kitchen_done"
        result["report"] = collect_case_report(case_id)
        result["output_dir"] = str(get_records_root() / case_id)
        return result

    # --- Room A ---
    if run_room_a and not skip_room_a_agent:
        if current_room(case_id) != "A":
            if current_room(case_id) == "1":
                from cold_box_room.r1.hallway import promote_to_room_a

                promote_to_room_a(case_id)
            elif current_room(case_id) != "A":
                raise RuntimeError(f"Cannot run Room A agent from room {current_room(case_id)}")
        preflight_room_a(case_id=case_id)
        from cold_box_room.agent.engine import run_room_a_agent

        room_a_result = run_room_a_agent(
            case_id=case_id,
            goal=result["room_a_goal"],
            max_turns=room_a_max_turns,
            model=model,
        )
        result["room_a_agent"] = room_a_result
        if not room_a_result.get("gate_open"):
            result["status"] = "room_a_failed"
            result["report"] = collect_case_report(case_id)
            result["output_dir"] = str(get_records_root() / case_id)
            return result
    elif skip_room_a_agent:
        fast_pass_room_a(case_id)
        result["room_a_agent"] = {"skipped": True, "gate_open": True}

    if current_room(case_id) == "A":
        if not room_a_checkpoint(case_id).get("ready_for_room2"):
            result["status"] = "room_a_failed"
            result["report"] = collect_case_report(case_id)
            result["output_dir"] = str(get_records_root() / case_id)
            return result
        promote_to_room2(case_id)
        result["kitchen"]["room"] = current_room(case_id)
        result["kitchen"]["sandbox_files"] = list_sandbox_files(case_id)

    # --- Room 2 (Layer 1) ---
    layer1_result: dict[str, Any] | None = None
    if run_layer1 and not skip_layer1_agent:
        preflight = preflight_agent(case_id=case_id)
        result["layer1_preflight"] = preflight
        from cold_box_room.agent.engine import run_layer1_agent

        layer1_result = run_layer1_agent(
            case_id=case_id,
            goal=result["layer1_goal"],
            max_turns=layer1_max_turns,
            model=model,
        )
        result["layer1_agent"] = layer1_result
        if not layer1_result.get("promoted_to_room_b"):
            result["status"] = "layer1_failed"
            result["report"] = collect_case_report(case_id)
            result["output_dir"] = str(get_records_root() / case_id)
            return result
    elif skip_layer1_agent:
        from cold_box_room.testing.hallway import bootstrap_case_to_room_b

        bootstrap_case_to_room_b(case_id)
        layer1_result = {"skipped": True, "promoted_to_room_b": True, "room": current_room(case_id)}
        result["layer1_agent"] = layer1_result

    if current_room(case_id) != "B":
        result["status"] = "layer1_failed"
        result["report"] = collect_case_report(case_id)
        result["output_dir"] = str(get_records_root() / case_id)
        return result

    # --- Room B ---
    if run_room_b and not skip_room_b_agent:
        preflight_room_b(case_id=case_id)
        from cold_box_room.agent.engine import run_room_b_agent

        room_b_result = run_room_b_agent(
            case_id=case_id,
            goal=result["room_b_goal"],
            max_turns=room_b_max_turns,
            model=model,
        )
        result["room_b_agent"] = room_b_result
        if not room_b_result.get("ready_for_room3"):
            result["status"] = "room_b_failed"
            result["report"] = collect_case_report(case_id)
            result["output_dir"] = str(get_records_root() / case_id)
            return result
    elif skip_room_b_agent:
        fast_pass_room_b(case_id)
        result["room_b_agent"] = {"skipped": True, "ready_for_room3": True}

    if current_room(case_id) == "B":
        if not room_b_checkpoint(case_id).get("ready_for_room3"):
            result["status"] = "room_b_failed"
            result["report"] = collect_case_report(case_id)
            result["output_dir"] = str(get_records_root() / case_id)
            return result
        promote_to_room3(case_id)

    # --- Room 3 ---
    if run_room3 and not skip_room3_agent:
        preflight_room3(case_id=case_id)
        from cold_box_room.agent.engine import run_room3_agent

        room3_result = run_room3_agent(
            case_id=case_id,
            goal=result["room3_goal"],
            max_turns=room3_max_turns,
            model=model,
        )
        result["room3_agent"] = room3_result
        if not room3_result.get("layer2_complete"):
            result["status"] = "room3_failed"
            result["report"] = collect_case_report(case_id)
            result["output_dir"] = str(get_records_root() / case_id)
            return result
    elif skip_room3_agent:
        result["room3_agent"] = {"skipped": True}

    report = collect_case_report(case_id)
    result["report"] = report
    result["output_dir"] = str(get_records_root() / case_id)
    result["status"] = "complete" if report.get("complete") else "incomplete"
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Full hallway E2E — R1 → A → 2 → B → 3 → case report",
    )
    parser.add_argument("--run-id", default="m57-jo-hallway")
    parser.add_argument("--case-id", default="")
    parser.add_argument("--evidence", default=str(DEFAULT_JO_E01))
    parser.add_argument("--room-a-goal", default="")
    parser.add_argument("--layer1-goal", default="")
    parser.add_argument("--room-b-goal", default="")
    parser.add_argument("--room3-goal", default="")
    parser.add_argument("--room-a-max-turns", type=int, default=15)
    parser.add_argument("--layer1-max-turns", type=int, default=45)
    parser.add_argument("--room-b-max-turns", type=int, default=15)
    parser.add_argument("--room3-max-turns", type=int, default=30)
    parser.add_argument("--model", default="")
    parser.add_argument(
        "--kitchen-only",
        action="store_true",
        help="Stop after R1 intake + promote to Room A (no API spend)",
    )
    parser.add_argument(
        "--skip-room-a-agent",
        action="store_true",
        help="Fast-pass Room A deterministically (tests/bootstrap)",
    )
    parser.add_argument(
        "--skip-layer1-agent",
        action="store_true",
        help="Bootstrap minimal Layer 1 pass instead of Room 2 agent",
    )
    parser.add_argument(
        "--skip-room-b-agent",
        action="store_true",
        help="Fast-pass Room B deterministically (tests/bootstrap)",
    )
    parser.add_argument(
        "--skip-room3-agent",
        action="store_true",
        help="Stop after Room 3 entrance without running Room 3 agent",
    )
    parser.add_argument(
        "--reuse-kitchen",
        action="store_true",
        help="Skip wipe + intake; run agents on existing workspace",
    )
    args = parser.parse_args(argv)

    out = run_hallway_e2e(
        run_id=args.run_id,
        case_id=args.case_id or None,
        evidence_path=Path(args.evidence),
        room_a_goal=args.room_a_goal or None,
        layer1_goal=args.layer1_goal or None,
        room_b_goal=args.room_b_goal or None,
        room3_goal=args.room3_goal or None,
        room_a_max_turns=args.room_a_max_turns,
        layer1_max_turns=args.layer1_max_turns,
        room_b_max_turns=args.room_b_max_turns,
        room3_max_turns=args.room3_max_turns,
        run_agents=not args.kitchen_only,
        skip_room_a_agent=args.skip_room_a_agent,
        skip_layer1_agent=args.skip_layer1_agent,
        skip_room_b_agent=args.skip_room_b_agent,
        skip_room3_agent=args.skip_room3_agent,
        model=args.model or None,
        reuse_kitchen=args.reuse_kitchen,
    )
    print(json.dumps(out, indent=2))
    if args.kitchen_only:
        return 0
    status = out.get("status")
    if status == "complete":
        return 0
    if status in {"room_a_failed", "layer1_failed", "room_b_failed", "room3_failed"}:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
