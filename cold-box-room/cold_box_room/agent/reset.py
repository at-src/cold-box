"""Reset Layer 1 agent run artifacts without touching R1 intake or hallway room."""

from __future__ import annotations

import shutil
from pathlib import Path

from cold_box_room.r1.paths import case_records_dir
from cold_box_room.r2.logbook_paths import (
    layer1_analyst_log_md_path,
    layer1_state_path,
    layer1_tool_log_md_path,
)
from cold_box_room.r2.output_files import scratch_dir
from cold_box_room.r2.tool_log import tool_log_path


def reset_layer1_agent_state(case_id: str) -> list[str]:
    """Remove scratch, logs, and agent history for a fresh R2 run."""
    removed: list[str] = []
    records = case_records_dir(case_id)

    scratch = scratch_dir(case_id)
    if scratch.is_dir():
        shutil.rmtree(scratch)
        removed.append(str(scratch))

    for path in (
        tool_log_path(case_id),
        records / "audit.jsonl",
        layer1_tool_log_md_path(case_id),
        layer1_analyst_log_md_path(case_id),
        layer1_state_path(case_id),
        records / "AGENT_RUN.jsonl",
    ):
        if path.is_file():
            path.unlink()
            removed.append(str(path))

    for pattern in ("agent_stdout*.log", "AGENT_RUN.jsonl.*"):
        for path in records.glob(pattern):
            path.unlink()
            removed.append(str(path))

    return removed
