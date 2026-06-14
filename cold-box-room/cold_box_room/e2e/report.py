"""Collect full case report after a hallway run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cold_box_room.r1.hallway import current_room
from cold_box_room.r1.paths import case_records_dir, hallway_state_path
from cold_box_room.r2.analyst_log import read_analyst_log as read_layer1_analyst_log
from cold_box_room.r2.checkpoint import r2_layer1_checkpoint
from cold_box_room.r2.logbook_paths import layer1_analyst_log_md_path, layer1_tool_log_md_path
from cold_box_room.room_3.analyst_log import read_analyst_log as read_layer2_analyst_log
from cold_box_room.room_3.checkpoint import room3_checkpoint
from cold_box_room.room_3.logbook_paths import (
    layer2_analyst_log_md_path,
    layer2_skill_log_md_path,
    layer2_tool_log_md_path,
)
from cold_box_room.room_a import room_a_checkpoint
from cold_box_room.room_b import room_b_checkpoint


def _read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def collect_case_report(case_id: str) -> dict[str, Any]:
    """Summarize case artifacts — Layer 1/2 write-ups, checkpoints, record paths."""
    records = case_records_dir(case_id)
    room = current_room(case_id)

    hallway: dict[str, Any] | None = None
    hpath = hallway_state_path(case_id)
    if hpath.is_file():
        hallway = json.loads(hpath.read_text(encoding="utf-8"))

    layer1_cp: dict[str, Any] | None = None
    layer2_cp: dict[str, Any] | None = None
    room_a_cp: dict[str, Any] | None = None
    room_b_cp: dict[str, Any] | None = None

    try:
        room_a_cp = room_a_checkpoint(case_id)
    except Exception:
        pass

    try:
        layer1_cp = r2_layer1_checkpoint(case_id)
    except Exception:
        pass

    try:
        room_b_cp = room_b_checkpoint(case_id)
    except Exception:
        pass

    try:
        layer2_cp = room3_checkpoint(case_id)
    except Exception:
        pass

    l1_analyst = None
    l2_analyst = None
    try:
        l1_analyst = read_layer1_analyst_log(case_id)
    except Exception:
        pass
    try:
        l2_analyst = read_layer2_analyst_log(case_id)
    except Exception:
        pass

    plan_a_md = records / "plan_a.md"
    plan_b_md = records / "plan_b.md"

    complete = bool(layer2_cp and layer2_cp.get("layer2_complete"))

    return {
        "case_id": case_id,
        "room": room,
        "complete": complete,
        "records_dir": str(records),
        "hallway": hallway,
        "checkpoints": {
            "room_a": room_a_cp,
            "layer1": layer1_cp,
            "room_b": room_b_cp,
            "layer2": layer2_cp,
        },
        "layer1": {
            "analyst_log": l1_analyst,
            "analyst_log_path": str(layer1_analyst_log_md_path(case_id)),
            "tool_log_path": str(layer1_tool_log_md_path(case_id)),
        "findings": ((l1_analyst or {}).get("parsed") or {}).get("findings"),
        "why": ((l1_analyst or {}).get("parsed") or {}).get("why"),
        "self_score": ((l1_analyst or {}).get("parsed") or {}).get("self_score"),
        },
        "layer2": {
            "analyst_log": l2_analyst,
            "analyst_log_path": str(layer2_analyst_log_md_path(case_id)),
            "skill_log_path": str(layer2_skill_log_md_path(case_id)),
            "tool_log_path": str(layer2_tool_log_md_path(case_id)),
        "findings": ((l2_analyst or {}).get("parsed") or {}).get("findings"),
        "why": ((l2_analyst or {}).get("parsed") or {}).get("why"),
        "corrections": ((l2_analyst or {}).get("parsed") or {}).get("corrections"),
        "self_score": ((l2_analyst or {}).get("parsed") or {}).get("self_score"),
        },
        "plans": {
            "plan_a_md": str(plan_a_md) if plan_a_md.is_file() else None,
            "plan_b_md": str(plan_b_md) if plan_b_md.is_file() else None,
            "plan_a_excerpt": (_read_text(plan_a_md) or "")[:2000] or None,
            "plan_b_excerpt": (_read_text(plan_b_md) or "")[:2000] or None,
        },
    }
