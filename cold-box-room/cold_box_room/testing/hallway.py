"""Hallway test bootstrap helpers."""

from __future__ import annotations

from typing import Any

from cold_box_room.r1.hallway import current_room, promote_to_room2, promote_to_room_a, promote_to_room_b
from cold_box_room.r2.checkpoint import submit_layer1_writeup
from cold_box_room.r2.tool_log import append_tool_log
from cold_box_room.room_a import fast_pass_room_a


def bootstrap_case_to_room2(case_id: str) -> dict[str, Any]:
    """R1 → A (fast pass) → R2 for unit tests that need a sandbox."""
    room = current_room(case_id)
    if room == "1":
        promote_to_room_a(case_id)
    if current_room(case_id) == "A":
        fast_pass_room_a(case_id)
    return promote_to_room2(case_id)


def bootstrap_case_to_room_b(case_id: str) -> dict[str, Any]:
    """R1 → A → R2 (minimal Layer 1 pass) → B for Room B unit tests."""
    bootstrap_case_to_room2(case_id)
    if current_room(case_id) != "2":
        raise RuntimeError(f"expected room 2 after bootstrap, got {current_room(case_id)}")
    append_tool_log(
        case_id=case_id,
        audit_id="CB-bootstrap-b",
        tool_id="SIFT-001",
        tool_name="mmls",
        purpose="bootstrap extraction",
        command=["mmls", "disk.E01"],
        input_relpath="disk.E01",
        exit_code=0,
        scratch_refs=["CB-bootstrap-b/stdout.txt"],
    )
    result = submit_layer1_writeup(
        case_id=case_id,
        findings="Bootstrap Layer 1 extraction for Room B tests.",
        self_score=9,
        why="Minimal harness pass for analysis planning tests.",
    )
    if current_room(case_id) != "B":
        return promote_to_room_b(case_id)
    return result.get("hallway") or {"room": current_room(case_id), "promoted": True}
