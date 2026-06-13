"""Harness-only tool log — SIFT runs and scratch analysis."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cold_box_room.r1.paths import case_records_dir


def tool_log_path(case_id: str):
    return case_records_dir(case_id) / "tool_log.jsonl"


def append_tool_log(
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
) -> None:
    record: dict[str, Any] = {
        "audit_id": audit_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "tool_id": tool_id,
        "tool_name": tool_name,
        "purpose": purpose,
        "command": command,
        "input_relpath": input_relpath,
        "exit_code": exit_code,
        "scratch_refs": scratch_refs or [],
        "stdout_preview": stdout_preview[:500],
        "error": error,
    }
    path = tool_log_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
