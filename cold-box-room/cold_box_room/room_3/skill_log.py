"""Harness-only Layer 2 skill run log."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cold_box_room.r1.paths import case_records_dir
from cold_box_room.r2.audit import next_audit_id
from cold_box_room.room_3.logbook_paths import SKILL_LOG_HEADING, layer2_skill_log_md_path


def skill_log_jsonl_path(case_id: str) -> Path:
    return case_records_dir(case_id) / "layer2_skill_log.jsonl"


def next_skill_run_id() -> str:
    return f"CB-skill-{next_audit_id().removeprefix('CB-')}"


def _ensure_skill_logbook_header(path: Path) -> None:
    if path.is_file():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"{SKILL_LOG_HEADING}\n\n"
        "_Harness only — each run_skill execution is appended automatically. Agent never edits this file._\n\n",
        encoding="utf-8",
    )


def append_skill_log(
    *,
    case_id: str,
    run_id: str,
    skill_id: str,
    journal_id: str,
    library_slug: str,
    input_relpath: str,
    ok: bool,
    audit_ids: list[str] | None = None,
    exit_code: int = 0,
    purpose: str = "",
    why: str = "",
    error: str = "",
    plan_step_id: int | None = None,
) -> None:
    refs = list(audit_ids or [])
    record: dict[str, Any] = {
        "run_id": run_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "skill_id": skill_id,
        "journal_id": journal_id,
        "library_slug": library_slug,
        "input_relpath": input_relpath,
        "ok": ok,
        "exit_code": exit_code,
        "audit_ids": refs,
        "purpose": purpose,
        "why": why,
        "error": error,
    }
    if plan_step_id is not None:
        record["plan_step_id"] = plan_step_id

    path = skill_log_jsonl_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    md_path = layer2_skill_log_md_path(case_id)
    _ensure_skill_logbook_header(md_path)
    lines = [
        f"## {run_id} — {skill_id} ({library_slug})",
        "",
        f"- **Journal:** `{journal_id}`",
        f"- **Input:** `{input_relpath}`",
        f"- **OK:** {ok}",
        f"- **Exit code:** {exit_code}",
    ]
    if purpose.strip():
        lines.append(f"- **Purpose:** {purpose.strip()}")
    if why.strip():
        lines.append(f"- **Why:** {why.strip()}")
    if plan_step_id is not None:
        lines.append(f"- **Plan step:** {plan_step_id}")
    if refs:
        lines.append("- **Harness audit ids:**")
        for aid in refs:
            lines.append(f"  - `{aid}`")
    if error:
        lines.append(f"- **Error:** {error}")
    lines.extend(["", ""])
    with md_path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def iter_skill_log_entries(case_id: str) -> Iterator[dict[str, Any]]:
    path = skill_log_jsonl_path(case_id)
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def read_skill_log(case_id: str, *, limit: int = 20) -> dict[str, Any]:
    entries = list(iter_skill_log_entries(case_id))
    md_path = layer2_skill_log_md_path(case_id)
    successful = sum(1 for row in entries if row.get("ok"))
    return {
        "jsonl_path": str(skill_log_jsonl_path(case_id).resolve()),
        "logbook_path": str(md_path.resolve()),
        "count": len(entries),
        "successful_runs": successful,
        "entries": entries[-limit:],
        "logbook_exists": md_path.is_file(),
        "logbook_content": md_path.read_text(encoding="utf-8") if md_path.is_file() else "",
    }


def successful_skill_run_ids(case_id: str) -> set[str]:
    return {str(row["run_id"]) for row in iter_skill_log_entries(case_id) if row.get("ok")}


def skill_run_audit_ids(case_id: str) -> set[str]:
    ids: set[str] = set()
    for row in iter_skill_log_entries(case_id):
        if row.get("ok"):
            for aid in row.get("audit_ids") or []:
                ids.add(str(aid))
    from cold_box_room.room_3.tool_log import iter_layer2_tool_log_entries

    for row in iter_layer2_tool_log_entries(case_id):
        run_id = str(row.get("skill_run_id") or "")
        if run_id and run_id in successful_skill_run_ids(case_id):
            ids.add(str(row.get("audit_id") or ""))
    ids.discard("")
    return ids
