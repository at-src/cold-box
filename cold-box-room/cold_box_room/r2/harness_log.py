"""Route harness tool rows to Layer 1 or Layer 2 logbooks."""

from __future__ import annotations

from typing import Any

from cold_box_room.r1.hallway import ROOM_3, current_room
from cold_box_room.r2.skill_harness import skill_harness_active
from cold_box_room.r2.tool_log import append_tool_log


def append_harness_tool_log(
    *,
    case_id: str,
    audit_id: str,
    tool_id: str,
    tool_name: str,
    purpose: str,
    command: list[str],
    input_relpath: str,
    exit_code: int,
    scratch_refs: list[str] | None = None,
    stdout_preview: str = "",
    error: str = "",
    why: str = "",
) -> None:
    """Layer 1 tool log in Room 2; Layer 2 tool log in Room 3 / skill scripts."""
    use_layer2 = skill_harness_active()
    if not use_layer2:
        try:
            use_layer2 = current_room(case_id) == ROOM_3
        except Exception:
            use_layer2 = False

    if use_layer2:
        from cold_box_room.skills.skill_runtime import get_runtime
        from cold_box_room.room_3.tool_log import append_layer2_tool_log

        skill_id = ""
        skill_run_id = ""
        journal_id = ""
        if skill_harness_active():
            runtime = get_runtime()
            skill_id = runtime.skill_id
            skill_run_id = runtime.skill_run_id
            journal_id = runtime.journal_id

        append_layer2_tool_log(
            case_id=case_id,
            audit_id=audit_id,
            tool_id=tool_id,
            tool_name=tool_name,
            purpose=purpose,
            command=command,
            input_relpath=input_relpath,
            exit_code=exit_code,
            scratch_refs=scratch_refs,
            stdout_preview=stdout_preview,
            error=error,
            skill_id=skill_id,
            skill_run_id=skill_run_id,
            journal_id=journal_id,
            why=why,
        )
        return

    append_tool_log(
        case_id=case_id,
        audit_id=audit_id,
        tool_id=tool_id,
        tool_name=tool_name,
        purpose=purpose,
        command=command,
        input_relpath=input_relpath,
        exit_code=exit_code,
        scratch_refs=scratch_refs,
        stdout_preview=stdout_preview,
        error=error,
    )
