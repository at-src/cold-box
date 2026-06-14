"""Layer 1 logbook file paths."""

from __future__ import annotations

from cold_box_room.r1.paths import case_records_dir

LAYER1_HEADING = "# Layer 1 — Evidence extraction"
TOOL_LOG_HEADING = f"{LAYER1_HEADING} (tool log)"
ANALYST_LOG_HEADING = f"{LAYER1_HEADING} (analyst log)"
MAX_PROMOTION_ATTEMPTS = 3


def layer1_tool_log_md_path(case_id: str):
    return case_records_dir(case_id) / "layer1_tool_log.md"


def layer1_analyst_log_md_path(case_id: str):
    return case_records_dir(case_id) / "layer1_analyst_log.md"


def layer1_state_path(case_id: str):
    return case_records_dir(case_id) / "layer1_state.json"
