"""Room 3 — Layer 2 analysis execution."""

from cold_box_room.planning.harness import apply_step_status
from cold_box_room.room_b import (
    get_plan_b_status,
    plan_b_md_path,
    plan_b_py_path,
    room_b_checkpoint,
)
from cold_box_room.room_3.analyst_log import read_analyst_log
from cold_box_room.room_3.checkpoint import (
    apply_plan_b_step_status,
    exit_layer2,
    extend_plan_b_step,
    layer2_readonly_summary,
    room3_checkpoint,
    submit_layer2_writeup,
)
from cold_box_room.room_3.skill_log import read_skill_log
from cold_box_room.room_3.tool_log import read_layer2_tool_log

ROOM = "3"


def get_room3_status(case_id: str):
    checkpoint = room3_checkpoint(case_id)
    plan_status = get_plan_b_status(case_id)
    return {**checkpoint, "plan_b": plan_status}


__all__ = [
    "ROOM",
    "apply_plan_b_step_status",
    "apply_step_status",
    "exit_layer2",
    "extend_plan_b_step",
    "get_plan_b_status",
    "get_room3_status",
    "layer2_readonly_summary",
    "plan_b_md_path",
    "plan_b_py_path",
    "read_analyst_log",
    "read_layer2_tool_log",
    "read_skill_log",
    "room3_checkpoint",
    "room_b_checkpoint",
    "submit_layer2_writeup",
]
