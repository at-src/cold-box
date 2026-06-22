"""Prod-like E2E — R1 → Room A → R2 → Layer 1 agent."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cold_box_room.agent.prompts import DEFAULT_LAYER1_GOAL, DEFAULT_ROOM_A_GOAL
from cold_box_room.e2e.workspace import force_remove_tree
from cold_box_room.r1.checkpoint import r1_checkpoint
from cold_box_room.r1.hallway import (
    current_room,
    promote_to_room2,
    promote_to_room_a,
    record_r1_check,
)
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import REPO_ROOT, get_records_root, get_staging_root
from cold_box_room.r2.paths import get_sandbox_root
from cold_box_room.r2.sandbox import list_sandbox_files
from cold_box_room.room_a import fast_pass_room_a, room_a_checkpoint

DEFAULT_JO_E01 = None  # no built-in default — pass --evidence explicitly
E2E_RUNS_ROOT = REPO_ROOT / "e2e-runs"


def prepare_fresh_workspace(*, run_id: str, wipe: bool = True) -> dict[str, str]:
    root = E2E_RUNS_ROOT / run_id
    if wipe and root.exists():
        force_remove_tree(root)

    # If the caller (e.g. the UI server) already configured COLD_BOX_ROOM_RECORDS,
    # honour it so case records land where the UI can find them.
    existing_records = os.environ.get("COLD_BOX_ROOM_RECORDS", "").strip()
    records_path = existing_records if existing_records else str(root / "records")

    paths = {
        "run_root": str(root),
        "r1_staging": str(root / "r1-staging"),
        "r2_sandbox": str(root / "r2-sandbox"),
        "records": records_path,
    }
    for key in ("r1_staging", "r2_sandbox", "records"):
        Path(paths[key]).mkdir(parents=True, exist_ok=True)

    os.environ["COLD_BOX_R1_STAGING"] = paths["r1_staging"]
    os.environ["COLD_BOX_R2_SANDBOX"] = paths["r2_sandbox"]
    os.environ["COLD_BOX_ROOM_RECORDS"] = paths["records"]
    os.environ.setdefault("COLD_BOX_ROOM_STRICT", "0")
    os.environ.setdefault("COLD_BOX_R1_STAT_ONLY", "1")
    os.environ.setdefault("ANTHROPIC_PROMPT_CACHE", "1")
    return paths


def bind_workspace(*, run_id: str) -> dict[str, str]:
    root = E2E_RUNS_ROOT / run_id
    if not root.is_dir():
        raise FileNotFoundError(f"E2E run not found: {root}")
    existing_records = os.environ.get("COLD_BOX_ROOM_RECORDS", "").strip()
    records_path = existing_records if existing_records else str(root / "records")
    paths = {
        "run_root": str(root),
        "r1_staging": str(root / "r1-staging"),
        "r2_sandbox": str(root / "r2-sandbox"),
        "records": records_path,
    }
    os.environ["COLD_BOX_R1_STAGING"] = paths["r1_staging"]
    os.environ["COLD_BOX_R2_SANDBOX"] = paths["r2_sandbox"]
    os.environ["COLD_BOX_ROOM_RECORDS"] = paths["records"]
    os.environ.setdefault("COLD_BOX_ROOM_STRICT", "0")
    os.environ.setdefault("COLD_BOX_R1_STAT_ONLY", "1")
    os.environ.setdefault("ANTHROPIC_PROMPT_CACHE", "1")
    return paths


def preflight_room_a(*, case_id: str) -> dict[str, Any]:
    from cold_box_room.agent.llm import anthropic_api_key, load_dotenv, prompt_cache_enabled

    load_dotenv()
    room = current_room(case_id)
    if room != "A":
        raise RuntimeError(f"Case {case_id!r} is room {room}, need room A before Room A agent")
    anthropic_api_key()
    return {"room": room, "prompt_cache": prompt_cache_enabled()}


def preflight_agent(*, case_id: str) -> dict[str, Any]:
    from cold_box_room.agent.llm import anthropic_api_key, load_dotenv, prompt_cache_enabled

    load_dotenv()
    room = current_room(case_id)
    if room != "2":
        raise RuntimeError(f"Case {case_id!r} is room {room}, need room 2 before Layer 1 agent")
    files = list_sandbox_files(case_id)
    if not files:
        raise RuntimeError(f"No files in R2 sandbox for {case_id!r}")
    anthropic_api_key()
    return {
        "room": room,
        "sandbox_files": files,
        "prompt_cache": prompt_cache_enabled(),
    }


def deliver_to_room_a(
    *,
    case_id: str,
    evidence_path: Path | None = None,
    link_only: bool = True,
) -> dict[str, Any]:
    """Kitchen — R1 intake, seal, check, promote to Room A (no sandbox yet)."""
    if not evidence_path:
        raise ValueError("evidence_path is required — pass a disk image, E01 chain, or directory")
    src = evidence_path.expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"Evidence not found: {src}")
    if not src.is_file() and not src.is_dir():
        raise FileNotFoundError(f"Evidence path is not a file or directory: {src}")

    intake = intake_case(case_id, source=src, link_only=link_only)
    check = record_r1_check(case_id)
    if not check["ok"]:
        raise RuntimeError(f"R1 checkpoint failed: {check}")

    hallway = promote_to_room_a(case_id)
    return {
        "ok": True,
        "case_id": case_id,
        "room": current_room(case_id),
        "intake": intake,
        "r1_checkpoint": check,
        "hallway": hallway,
        "paths": {
            "r1_staging": str(get_staging_root()),
            "r2_sandbox": str(get_sandbox_root()),
            "records": str(get_records_root()),
        },
    }


def deliver_to_room2(
    *,
    case_id: str,
    evidence_path: Path | None = None,
    link_only: bool = True,
    skip_room_a_agent: bool = False,
) -> dict[str, Any]:
    """Kitchen — R1 → A → (fast pass Room A) → R2 sandbox materialized."""
    kitchen_a = deliver_to_room_a(
        case_id=case_id,
        evidence_path=evidence_path,
        link_only=link_only,
    )
    if skip_room_a_agent:
        fast_pass_room_a(case_id)
    elif not room_a_checkpoint(case_id).get("ready_for_room2"):
        raise RuntimeError(
            "Room A gate not open — run Room A agent or pass skip_room_a_agent=True for bootstrap"
        )

    hallway = promote_to_room2(case_id)
    sandbox_files = list_sandbox_files(case_id)
    return {
        **kitchen_a,
        "room": current_room(case_id),
        "room_a_checkpoint": room_a_checkpoint(case_id),
        "hallway_r2": hallway,
        "sandbox_files": sandbox_files,
    }


def run_layer1_e2e(
    *,
    run_id: str,
    case_id: str | None = None,
    evidence_path: Path | None = None,
    goal: str | None = None,
    room_a_goal: str | None = None,
    max_turns: int = 45,
    room_a_max_turns: int = 15,
    run_agent: bool = True,
    run_room_a: bool = True,
    model: str | None = None,
    reuse_kitchen: bool = False,
    skip_room_a_agent: bool = False,
    skip_layer1_agent: bool = False,
) -> dict[str, Any]:
    case_id = case_id or run_id

    if reuse_kitchen:
        paths = bind_workspace(run_id=run_id)
        kitchen = {
            "ok": True,
            "case_id": case_id,
            "room": current_room(case_id),
            "reused": True,
            "sandbox_files": list_sandbox_files(case_id) if current_room(case_id) == "2" else [],
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
        "goal": goal or DEFAULT_LAYER1_GOAL,
        "prompt_cache": os.environ.get("ANTHROPIC_PROMPT_CACHE", "1"),
    }

    if not run_agent:
        result["room_a_agent"] = None
        result["agent"] = None
        result["status"] = "kitchen_done"
        return result

    room_a_result = None
    if run_room_a and not skip_room_a_agent:
        if current_room(case_id) != "A":
            if current_room(case_id) == "1":
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
            result["agent"] = None
            result["status"] = "room_a_failed"
            return result
    elif skip_room_a_agent:
        fast_pass_room_a(case_id)
        result["room_a_agent"] = {"skipped": True, "gate_open": True}

    if current_room(case_id) == "A":
        promote_to_room2(case_id)
        result["kitchen"]["room"] = current_room(case_id)
        result["kitchen"]["sandbox_files"] = list_sandbox_files(case_id)

    if skip_layer1_agent:
        from cold_box_room.testing.hallway import bootstrap_case_to_room_b

        bootstrap_case_to_room_b(case_id)
        agent_result = {
            "skipped": True,
            "promoted_to_room_b": True,
            "room": current_room(case_id),
        }
        result["agent"] = agent_result
        result["status"] = "complete"
        result["output_dir"] = str(get_records_root() / case_id)
        return result

    preflight = preflight_agent(case_id=case_id)
    result["preflight"] = preflight

    from cold_box_room.agent.engine import run_layer1_agent

    agent_result = run_layer1_agent(
        case_id=case_id,
        goal=result["goal"],
        max_turns=max_turns,
        model=model,
    )
    result["agent"] = agent_result
    result["status"] = "complete" if agent_result.get("promoted_to_room_b") else "layer1_failed"
    result["output_dir"] = str(get_records_root() / case_id)
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Layer 1 E2E — R1 → Room A → R2 → optional agents",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--case-id", default="")
    parser.add_argument("--evidence", required=True, help="Disk image, E01 chain, or directory")
    parser.add_argument("--goal", default="")
    parser.add_argument("--room-a-goal", default="")
    parser.add_argument("--max-turns", type=int, default=45)
    parser.add_argument("--room-a-max-turns", type=int, default=15)
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
        "--reuse-kitchen",
        action="store_true",
        help="Skip wipe + intake; run agents on existing workspace",
    )
    args = parser.parse_args(argv)

    out = run_layer1_e2e(
        run_id=args.run_id,
        case_id=args.case_id or None,
        evidence_path=Path(args.evidence),
        goal=args.goal or None,
        room_a_goal=args.room_a_goal or None,
        max_turns=args.max_turns,
        room_a_max_turns=args.room_a_max_turns,
        run_agent=not args.kitchen_only,
        skip_room_a_agent=args.skip_room_a_agent,
        skip_layer1_agent=args.skip_layer1_agent,
        model=args.model or None,
        reuse_kitchen=args.reuse_kitchen,
    )
    print(json.dumps(out, indent=2))
    if args.kitchen_only:
        return 0
    if out.get("status") == "room_a_failed":
        return 2
    promoted = out.get("agent", {}).get("promoted_to_room_b")
    return 0 if promoted else 1


if __name__ == "__main__":
    raise SystemExit(main())
