"""Room A — extraction planning (isolated; uses shared ``planning`` blueprint)."""

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

ROOM = "a"


def plan_a_md_path(case_id: str):
    return plan_md_path(case_id, room=ROOM)


def plan_a_py_path(case_id: str):
    return plan_py_path(case_id, room=ROOM)


def write_plan_a_md(*, case_id: str, markdown: str):
    return write_plan_md(case_id=case_id, markdown=markdown, room=ROOM)


def formalize_plan_a(*, case_id: str):
    return formalize_plan_md(case_id=case_id, room=ROOM)


def extend_plan_a_step(*, case_id: str, title: str, reason: str, tool_id: str = ""):
    return extend_plan_step(
        case_id=case_id,
        room=ROOM,
        title=title,
        reason=reason,
        tool_id=tool_id,
    )


def room_a_checkpoint(case_id: str):
    return planning_checkpoint(case_id, room=ROOM)


def apply_plan_a_step_status(**kwargs):
    return apply_step_status(room=ROOM, **kwargs)


def get_plan_a_status(case_id: str):
    checkpoint = planning_checkpoint(case_id, room=ROOM)
    py_path = plan_py_path(case_id, room=ROOM)
    steps = []
    if py_path.is_file():
        doc = load_plan_py(py_path, room=ROOM)
        steps = [s.to_dict() for s in doc.steps]
    return {**checkpoint, "steps": steps}


def _bootstrap_resolve_plan_a(case_id: str) -> None:
    """Resolve fast-pass plan steps for test/kitchen bootstrap (not an agent run)."""
    py_path = plan_py_path(case_id, room=ROOM)
    if not py_path.is_file():
        return
    doc = load_plan_py(py_path, room=ROOM)
    for step in doc.steps:
        if step.step_id == 1:
            apply_step_status(
                case_id=case_id,
                room=ROOM,
                step_id=step.step_id,
                status="passed",
                proof={
                    "audit_id": "CB-bootstrap",
                    "exit_code": 0,
                    "scratch_refs": ["CB-bootstrap/stdout.txt"],
                    "note": "bootstrap fast-pass",
                },
            )
        else:
            apply_step_status(
                case_id=case_id,
                room=ROOM,
                step_id=step.step_id,
                status="not_relevant",
                proof={"note": "bootstrap fast-pass — out of scope for unit test kitchen"},
            )


def fast_pass_room_a(case_id: str, *, markdown: str | None = None) -> dict:
    """Deterministic Room A completion for tests/kitchen bootstrap (not an agent run)."""
    from cold_box_room.planning.markdown import PLAN_A_SKELETON
    from cold_box_room.r1.hallway import current_room, promote_to_room_a

    if current_room(case_id) == "1":
        promote_to_room_a(case_id)
    body = markdown or PLAN_A_SKELETON.format(case_id=case_id).replace(
        "## Step 1 — (what to extract)",
        "## Step 1 — Image metadata",
    ).replace(
        "**Reason:** (why this artifact class matters for this case)",
        "**Reason:** Establish chain of custody and partition layout",
    )
    if "## Step 2" not in body:
        body += """

## Step 2 — User artifact sweep

**Reason:** Inventory profiles and high-value paths on disk
"""
    write_plan_a_md(case_id=case_id, markdown=body)
    result = formalize_plan_a(case_id=case_id)
    _bootstrap_resolve_plan_a(case_id)
    checkpoint = room_a_checkpoint(case_id)
    return {
        **result,
        "gate_open": checkpoint.get("ready_for_room2", False),
        "ready_for_room2": checkpoint.get("ready_for_room2", False),
        "checkpoint": checkpoint,
    }


__all__ = [
    "ROOM",
    "all_steps_resolved",
    "apply_plan_a_step_status",
    "apply_step_status",
    "assert_tool_allowed_in_room",
    "compute_plan_score",
    "extend_plan_a_step",
    "fast_pass_room_a",
    "formalize_plan",
    "formalize_plan_a",
    "get_plan_a_status",
    "plan_a_md_path",
    "plan_a_py_path",
    "room_a_checkpoint",
    "write_plan_a_md",
]
