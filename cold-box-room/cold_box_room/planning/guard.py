"""Block extraction/analysis execution inside planning rooms A and B."""

from __future__ import annotations

PLANNING_ROOMS = frozenset({"A", "B"})

ROOM_A_ALLOWED_TOOLS = frozenset(
    {
        "list_sift_tools",
        "describe_sift_tool",
        "write_plan_a_md",
        "formalize_plan_a",
        "get_room_a_status",
        "room_a_checkpoint",
        "return_to_room",
        "list_unlocked_rooms",
    }
)

ROOM_B_ALLOWED_TOOLS = frozenset(
    {
        "list_sift_tools",
        "describe_sift_tool",
        "list_skills",
        "describe_skill",
        "write_plan_b_md",
        "formalize_plan_b",
        "get_room_b_status",
        "room_b_checkpoint",
        "read_layer1_tool_log",
        "read_layer1_analyst_log",
        "get_layer1_status",
        "return_to_room",
        "list_unlocked_rooms",
    }
)

SKILLS_EXECUTION_TOOLS = frozenset({"run_skill"})

ROOM_3_ALLOWED_TOOLS = frozenset(
    {
        "list_skills",
        "describe_skill",
        "list_sift_tools",
        "describe_sift_tool",
        "run_skill",
        "read_layer1_tool_log",
        "read_layer1_analyst_log",
        "get_layer1_status",
        "read_layer2_skill_log",
        "read_layer2_tool_log",
        "read_layer2_analyst_log",
        "get_plan_b_status",
        "apply_plan_b_step_status",
        "extend_plan_b_step",
        "get_room3_status",
        "submit_layer2_writeup",
        "exit_layer2",
        "list_sandbox_files",
        "analyze_scratch",
        "return_to_room",
        "list_unlocked_rooms",
    }
)

R2_EXECUTION_TOOLS = frozenset(
    {
        "list_sandbox_files",
        "list_sift_tools",
        "describe_sift_tool",
        "run_sift_tool",
        "analyze_scratch",
        "read_layer1_tool_log",
        "read_layer1_analyst_log",
        "get_layer1_status",
        "submit_layer1_writeup",
        "extend_plan_a_step",
        "get_plan_a_status",
        "apply_plan_a_step_status",
        "return_to_room",
        "list_unlocked_rooms",
    }
)

LAYER1_DIRECT_TOOLS = frozenset(
    {
        "run_sift_tool",
        "submit_layer1_writeup",
        "extend_plan_a_step",
        "apply_plan_a_step_status",
        "get_plan_a_status",
    }
)

EXTRACTION_EXECUTION_TOOLS = LAYER1_DIRECT_TOOLS | frozenset(
    {
        "analyze_scratch",
    }
)

LAYER2_EXECUTION_TOOLS = frozenset(
    {
        "run_skill",
        "submit_layer2_writeup",
        "apply_plan_b_step_status",
    }
)

PLANNING_ONLY_TOOLS_A = frozenset(
    {
        "write_plan_a_md",
        "formalize_plan_a",
    }
)

PLANNING_ONLY_TOOLS_B = frozenset(
    {
        "write_plan_b_md",
        "formalize_plan_b",
    }
)

REVISIT_TOOLS = frozenset({"return_to_room", "list_unlocked_rooms"})


class PlanningRoomGuardError(Exception):
    """Agent attempted a tool in the wrong room."""


def _normalize_room(room: str | int) -> str:
    return str(room).strip().upper()


def assert_tool_allowed_in_room(*, tool_name: str, room: str | int) -> None:
    """Deterministic wall — each room gets its own tool surface."""
    room_label = _normalize_room(room)

    if tool_name in REVISIT_TOOLS:
        return

    if room_label == "A":
        if tool_name in EXTRACTION_EXECUTION_TOOLS | SKILLS_EXECUTION_TOOLS | LAYER2_EXECUTION_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} blocked in Room A — planning only. "
                "Write plan_a.md, then formalize to plan_a.py."
            )
        if tool_name not in ROOM_A_ALLOWED_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} not available in Room A. "
                f"Allowed: {', '.join(sorted(ROOM_A_ALLOWED_TOOLS))}"
            )
        return

    if room_label == "B":
        if tool_name in EXTRACTION_EXECUTION_TOOLS | SKILLS_EXECUTION_TOOLS | LAYER2_EXECUTION_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} blocked in Room B — analysis planning only. "
                "Write plan_b.md, then formalize to plan_b.py."
            )
        if tool_name not in ROOM_B_ALLOWED_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} not available in Room B. "
                f"Allowed: {', '.join(sorted(ROOM_B_ALLOWED_TOOLS))}"
            )
        return

    if room_label == "2":
        if tool_name in PLANNING_ONLY_TOOLS_A | PLANNING_ONLY_TOOLS_B | LAYER2_EXECUTION_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} blocked in Room 2 — use extraction tools or return_to_room for planning fixes."
            )
        if tool_name not in R2_EXECUTION_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} not available in Room 2 execution."
            )
        return

    if room_label == "3":
        if tool_name in LAYER1_DIRECT_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} blocked in Room 3 — Layer 1 extraction runs in Room 2 only. "
                "Call return_to_room(case_id, room='2', reason=...) to add extractions "
                "(extend_plan_a_step + run_sift_tool), then return_to_room back to 3."
            )
        if tool_name in PLANNING_ONLY_TOOLS_A | PLANNING_ONLY_TOOLS_B:
            raise PlanningRoomGuardError(
                f"{tool_name} blocked in Room 3 — use return_to_room to revise plan_b in Room B."
            )
        if tool_name not in ROOM_3_ALLOWED_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} not available in Room 3. "
                f"Allowed: {', '.join(sorted(ROOM_3_ALLOWED_TOOLS))}"
            )
        return


PLANNING_ALLOWED_TOOLS = ROOM_A_ALLOWED_TOOLS
