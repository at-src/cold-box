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
    }
)

ROOM_B_ALLOWED_TOOLS = frozenset(
    {
        "list_sift_tools",
        "describe_sift_tool",
        "write_plan_b_md",
        "formalize_plan_b",
        "get_room_b_status",
        "room_b_checkpoint",
        "read_layer1_tool_log",
        "read_layer1_analyst_log",
        "get_layer1_status",
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
    }
)

EXTRACTION_EXECUTION_TOOLS = frozenset(
    {
        "run_sift_tool",
        "analyze_scratch",
        "submit_layer1_writeup",
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


class PlanningRoomGuardError(Exception):
    """Agent attempted a tool in the wrong room."""


def _normalize_room(room: str | int) -> str:
    return str(room).strip().upper()


def assert_tool_allowed_in_room(*, tool_name: str, room: str | int) -> None:
    """Deterministic wall — each room gets its own tool surface."""
    room_label = _normalize_room(room)

    if room_label == "A":
        if tool_name in EXTRACTION_EXECUTION_TOOLS:
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
        if tool_name in EXTRACTION_EXECUTION_TOOLS:
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
        if tool_name in PLANNING_ONLY_TOOLS_A | PLANNING_ONLY_TOOLS_B:
            raise PlanningRoomGuardError(
                f"{tool_name} blocked in Room 2 — planning was Room A/B. "
                "Use extend_plan_a_step if you need new extraction checkpoints."
            )
        if tool_name not in R2_EXECUTION_TOOLS:
            raise PlanningRoomGuardError(
                f"{tool_name} not available in Room 2 execution."
            )
        return

    if room_label == "3":
        raise PlanningRoomGuardError(
            f"{tool_name} blocked — Room 3 analysis execution is not implemented yet."
        )


# Backward-compatible alias
PLANNING_ALLOWED_TOOLS = ROOM_A_ALLOWED_TOOLS
