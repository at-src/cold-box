"""Harness-only Layer 2 tool log — SIFT runs invoked inside skill scripts (Room 3)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cold_box_room.r1.paths import case_records_dir
from cold_box_room.room_3.logbook_paths import TOOL_LOG_HEADING, layer2_tool_log_md_path


def tool_log_jsonl_path(case_id: str) -> Path:
    return case_records_dir(case_id) / "layer2_tool_log.jsonl"


def _ensure_tool_logbook_header(path: Path) -> None:
    if path.is_file():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"{TOOL_LOG_HEADING}\n\n"
        "_Harness only — nested SIFT/scratch runs from run_skill scripts. Agent never edits this file._\n\n",
        encoding="utf-8",
    )


def append_layer2_tool_log(
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
    skill_id: str = "",
    skill_run_id: str = "",
    journal_id: str = "",
    why: str = "",
) -> None:
    refs = scratch_refs or []
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
        "exit_code": exit_code,
        "scratch_refs": refs,
        "stdout_preview": stdout_preview[:500],
        "error": error,
        "skill_id": skill_id,
        "skill_run_id": skill_run_id,
        "journal_id": journal_id,
    }
    path = tool_log_jsonl_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    md_path = layer2_tool_log_md_path(case_id)
    _ensure_tool_logbook_header(md_path)
    cmd = " ".join(command)
    lines = [
        f"## {audit_id} — {tool_id} {tool_name}",
        "",
        f"- **Purpose:** {purpose}",
    ]
    if skill_id:
        lines.append(f"- **Skill:** `{skill_id}` run `{skill_run_id}` journal `{journal_id}`")
    lines.extend(
        [
            f"- **Input:** `{input_relpath}`",
            f"- **Command:** `{cmd}`",
            f"- **Exit code:** {exit_code}",
        ]
    )
    if refs:
        lines.append("- **Scratch:**")
        for ref in refs:
            lines.append(f"  - `{ref}`")
    if stdout_preview.strip():
        preview = stdout_preview.strip().replace("\n", "\n  ")
        lines.extend(["- **Preview:**", f"  ```", f"  {preview}", f"  ```"])
    if error:
        lines.append(f"- **Error:** {error}")
    lines.extend(["", ""])
    with md_path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def iter_layer2_tool_log_entries(case_id: str) -> Iterator[dict[str, Any]]:
    path = tool_log_jsonl_path(case_id)
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def read_layer2_tool_log(case_id: str, *, limit: int = 20) -> dict[str, Any]:
    entries = list(iter_layer2_tool_log_entries(case_id))
    md_path = layer2_tool_log_md_path(case_id)
    return {
        "jsonl_path": str(tool_log_jsonl_path(case_id).resolve()),
        "logbook_path": str(md_path.resolve()),
        "heading": TOOL_LOG_HEADING,
        "count": len(entries),
        "successful_runs": sum(1 for row in entries if int(row.get("exit_code", -1)) == 0),
        "entries": entries[-limit:],
        "logbook_exists": md_path.is_file(),
        "logbook_content": md_path.read_text(encoding="utf-8") if md_path.is_file() else "",
        "harness_only": True,
    }
