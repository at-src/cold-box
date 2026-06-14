"""Append steps to a formalized plan during R2 execution."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.models import PlanDocument, PlanStep
from cold_box_room.planning.paths import plan_py_path
from cold_box_room.planning.plan_py import load_plan_py, validate_plan_structure, write_plan_py
from cold_box_room.planning.scoring import compute_plan_score


class PlanExtendError(Exception):
    """Could not append a plan step."""


def extend_plan_step(
    *,
    case_id: str,
    room: str,
    title: str,
    reason: str,
    tool_id: str = "",
) -> dict[str, Any]:
    """R2/R3 execution — add a checkpoint row to plan_*.py (same +1/-1 scoring rules)."""
    title = title.strip()
    reason = reason.strip()
    if not title:
        raise PlanExtendError("title is required")
    if not reason:
        raise PlanExtendError("reason is required")

    path = plan_py_path(case_id, room=room)
    if not path.is_file():
        raise PlanExtendError(
            f"missing {path.name} — complete Room {room.upper()} planning before extending in execution"
        )

    doc = load_plan_py(path, room=room)
    next_id = max((s.step_id for s in doc.steps), default=0) + 1
    new_step = PlanStep(
        step_id=next_id,
        title=title,
        reason=reason,
        tool_id=tool_id.strip(),
        status="pending",
        proof={"added_in_execution": True, "room": room.upper()},
    )
    updated = PlanDocument(
        case_id=doc.case_id or case_id,
        room=doc.room or room.upper(),
        steps=[*doc.steps, new_step],
        attestation=doc.attestation,
    )
    errors = validate_plan_structure(updated)
    if errors:
        raise PlanExtendError("; ".join(errors))

    write_plan_py(path, updated, room=room)
    score = compute_plan_score(updated)
    return {
        "ok": True,
        "case_id": case_id,
        "room": room.upper(),
        "step_id": next_id,
        "title": title,
        "reason": reason,
        "status": "pending",
        "step_count": len(updated.steps),
        "plan_score": score,
        "plan_py": str(path),
    }
