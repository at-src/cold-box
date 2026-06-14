"""Room B — analysis planning (isolated; uses shared ``planning`` blueprint)."""

from cold_box_room.planning.checkpoint import (
    formalize_plan_md,
    planning_checkpoint,
    write_plan_md,
)
from cold_box_room.planning.extend import extend_plan_step
from cold_box_room.planning.formalize import formalize_plan
from cold_box_room.planning.guard import assert_tool_allowed_in_room
from cold_box_room.planning.harness import apply_step_status
from cold_box_room.planning.paths import plan_md_path, plan_py_path
from cold_box_room.planning.plan_py import load_plan_py
from cold_box_room.planning.scoring import all_steps_resolved, compute_plan_score

ROOM = "b"


def plan_b_md_path(case_id: str):
    return plan_md_path(case_id, room=ROOM)


def plan_b_py_path(case_id: str):
    return plan_py_path(case_id, room=ROOM)


def write_plan_b_md(*, case_id: str, markdown: str):
    return write_plan_md(case_id=case_id, markdown=markdown, room=ROOM)


def formalize_plan_b(*, case_id: str):
    return formalize_plan_md(case_id=case_id, room=ROOM)


def extend_plan_b_step(*, case_id: str, title: str, reason: str, tool_id: str = ""):
    return extend_plan_step(
        case_id=case_id,
        room=ROOM,
        title=title,
        reason=reason,
        tool_id=tool_id,
    )


def room_b_checkpoint(case_id: str):
    return planning_checkpoint(case_id, room=ROOM)


def apply_plan_b_step_status(**kwargs):
    return apply_step_status(room=ROOM, **kwargs)


def get_plan_b_status(case_id: str):
    checkpoint = planning_checkpoint(case_id, room=ROOM)
    py_path = plan_py_path(case_id, room=ROOM)
    steps = []
    if py_path.is_file():
        doc = load_plan_py(py_path, room=ROOM)
        steps = [s.to_dict() for s in doc.steps]
    return {**checkpoint, "steps": steps}


def fast_pass_room_b(case_id: str, *, markdown: str | None = None) -> dict:
    """Deterministic Room B completion for tests (not an agent run)."""
    from cold_box_room.planning.markdown import PLAN_B_SKELETON
    from cold_box_room.r1.hallway import current_room, require_room

    require_room(case_id, "B")
    body = markdown or PLAN_B_SKELETON.format(case_id=case_id)
    write_plan_b_md(case_id=case_id, markdown=body)
    result = formalize_plan_b(case_id=case_id)
    checkpoint = room_b_checkpoint(case_id)
    return {
        **result,
        "gate_open": checkpoint.get("ready_for_room3", False),
        "ready_for_room3": checkpoint.get("ready_for_room3", False),
        "checkpoint": checkpoint,
    }


__all__ = [
    "ROOM",
    "all_steps_resolved",
    "apply_plan_b_step_status",
    "apply_step_status",
    "assert_tool_allowed_in_room",
    "compute_plan_score",
    "extend_plan_b_step",
    "fast_pass_room_b",
    "formalize_plan",
    "formalize_plan_b",
    "get_plan_b_status",
    "plan_b_md_path",
    "plan_b_py_path",
    "room_b_checkpoint",
    "write_plan_b_md",
]
