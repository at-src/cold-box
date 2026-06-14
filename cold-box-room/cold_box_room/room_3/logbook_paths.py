"""Layer 2 logbook file paths."""

from __future__ import annotations

from cold_box_room.r1.paths import case_records_dir

LAYER2_HEADING = "# Layer 2 — Analysis"
TOOL_LOG_HEADING = f"{LAYER2_HEADING} (tool log)"
SKILL_LOG_HEADING = f"{LAYER2_HEADING} (skill log)"
ANALYST_LOG_HEADING = f"{LAYER2_HEADING} (analyst log)"
MAX_PROMOTION_ATTEMPTS = 3


def layer2_tool_log_md_path(case_id: str):
    return case_records_dir(case_id) / "layer2_tool_log.md"


def layer2_skill_log_md_path(case_id: str):
    return case_records_dir(case_id) / "layer2_skill_log.md"


def layer2_analyst_log_md_path(case_id: str):
    return case_records_dir(case_id) / "layer2_analyst_log.md"


def layer2_state_path(case_id: str):
    return case_records_dir(case_id) / "layer2_state.json"


def layer2_skill_log_jsonl_path(case_id: str):
    return case_records_dir(case_id) / "layer2_skill_log.jsonl"
