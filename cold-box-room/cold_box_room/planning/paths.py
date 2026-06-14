"""Paths for plan_a / plan_b artifacts under case records."""

from __future__ import annotations

from pathlib import Path

from cold_box_room.r1.paths import case_records_dir


def plan_md_path(case_id: str, *, room: str) -> Path:
    letter = room.strip().lower()
    return case_records_dir(case_id) / f"plan_{letter}.md"


def plan_py_path(case_id: str, *, room: str) -> Path:
    letter = room.strip().lower()
    return case_records_dir(case_id) / f"plan_{letter}.py"


def plan_var_name(room: str) -> str:
    return f"PLAN_{room.strip().upper()}"
