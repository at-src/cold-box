"""MCP-only case setup helpers for the Claude Code parallel track."""

from __future__ import annotations

import json
from typing import Any

from cold_box_room.r1.hallway import current_room, list_room_revisits, unlocked_rooms
from cold_box_room.r1.paths import (
    case_records_dir,
    case_staging_dir,
    get_records_root,
    get_staging_root,
    hallway_state_path,
)
from cold_box_room.r1.seal import is_sealed, seal_record_path
from cold_box_room.r2.paths import case_sandbox_dir, get_sandbox_root


def handle_get_hallway_status(case_id: str) -> dict[str, Any]:
    """Where the case is in the hallway and which rooms are unlocked."""
    try:
        room = current_room(case_id)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}

    payload: dict[str, Any] = {
        "ok": True,
        "case_id": case_id,
        "room": room,
        "sealed": is_sealed(case_id),
        "unlocked_rooms": sorted(unlocked_rooms(case_id)),
        "revisits": list_room_revisits(case_id),
    }
    hall_path = hallway_state_path(case_id)
    if hall_path.is_file():
        payload["hallway"] = json.loads(hall_path.read_text(encoding="utf-8"))
    seal_path = seal_record_path(case_id)
    if seal_path.is_file():
        payload["seal"] = json.loads(seal_path.read_text(encoding="utf-8"))
    manifest = case_records_dir(case_id) / "manifest.json"
    if manifest.is_file():
        manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
        payload["staged_files"] = [
            row.get("path") for row in manifest_data.get("files") or [] if row.get("path")
        ]
    return payload


def handle_get_case_paths(case_id: str) -> dict[str, Any]:
    """Filesystem roots for this case (read-only reference for the operator)."""
    return {
        "ok": True,
        "case_id": case_id,
        "paths": {
            "r1_staging": str(case_staging_dir(case_id)),
            "r2_sandbox": str(case_sandbox_dir(case_id)),
            "records": str(case_records_dir(case_id)),
            "audit_log": str(case_records_dir(case_id) / "audit.jsonl"),
            "hallway_state": str(hallway_state_path(case_id)),
        },
        "roots": {
            "COLD_BOX_R1_STAGING": str(get_staging_root()),
            "COLD_BOX_R2_SANDBOX": str(get_sandbox_root()),
            "COLD_BOX_ROOM_RECORDS": str(get_records_root()),
        },
    }
