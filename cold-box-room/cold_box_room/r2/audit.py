"""Append-only audit log for tool executions."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from cold_box_room.r1.paths import case_records_dir


def audit_log_path(case_id: str):
    return case_records_dir(case_id) / "audit.jsonl"


def find_prior_success(
    case_id: str,
    *,
    tool_name: str,
    input_sha256: str,
) -> dict[str, Any] | None:
    """Return the most recent successful audit row for the same tool + evidence hash."""
    path = audit_log_path(case_id)
    if not path.is_file() or not input_sha256:
        return None
    for line in reversed(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("tool_name") != tool_name:
            continue
        if row.get("input_sha256") != input_sha256:
            continue
        exit_code = row.get("exit_code")
        if exit_code is None or int(exit_code) != 0:
            continue
        return row
    return None


def next_audit_id() -> str:
    return f"CB-{uuid.uuid4().hex[:12]}"


def append_audit(
    *,
    case_id: str,
    audit_id: str,
    tool_id: str,
    tool_name: str,
    purpose: str,
    why: str,
    command: list[str],
    input_relpath: str,
    input_sha256: str,
    exit_code: int,
    elapsed_ms: float,
    output_files: list[str] | None = None,
    stdout_preview: str = "",
    error: str = "",
) -> str:
    record: dict[str, Any] = {
        "audit_id": audit_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "tool_id": tool_id,
        "tool_name": tool_name,
        "purpose": purpose,
        "why": why,
        "command": command,
        "input_relpath": input_relpath,
        "input_sha256": input_sha256,
        "exit_code": exit_code,
        "elapsed_ms": round(elapsed_ms, 2),
        "output_files": output_files or [],
        "stdout_preview": stdout_preview[:2000],
        "error": error,
    }
    path = audit_log_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return audit_id
