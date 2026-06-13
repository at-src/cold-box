"""Hallway state — which room the case is in."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cold_box_room.r1.checkpoint import r1_checkpoint, require_r1_checkpoint
from cold_box_room.r1.paths import StagingError, hallway_state_path


def _load(case_id: str) -> dict[str, Any]:
    path = hallway_state_path(case_id)
    if not path.is_file():
        raise StagingError(f"No hallway state for {case_id!r} — run intake first.")
    return json.loads(path.read_text(encoding="utf-8"))


def _save(case_id: str, data: dict[str, Any]) -> None:
    hallway_state_path(case_id).write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def init_hallway(case_id: str) -> dict[str, Any]:
    data = {
        "case_id": case_id,
        "room": 1,
        "r1_checkpoint": None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save(case_id, data)
    return data


def current_room(case_id: str) -> int:
    return int(_load(case_id).get("room", 1))


def require_room(case_id: str, room: int) -> None:
    actual = current_room(case_id)
    if actual != room:
        raise StagingError(
            f"Case {case_id!r} is in room {actual}, required room {room}"
        )


def record_r1_check(case_id: str) -> dict[str, Any]:
    check = r1_checkpoint(case_id)
    data = _load(case_id)
    data["r1_checkpoint"] = check
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save(case_id, data)
    return check


def promote_to_room2(case_id: str) -> dict[str, Any]:
    require_room(case_id, 1)
    require_r1_checkpoint(case_id)
    check = record_r1_check(case_id)

    from cold_box_room.r2.sandbox import materialize_sandbox

    sandbox_record = materialize_sandbox(case_id)

    data = _load(case_id)
    data["room"] = 2
    data["promoted_at"] = datetime.now(timezone.utc).isoformat()
    data["r1_checkpoint"] = check
    data["r2_sandbox"] = {
        "sandbox_dir": sandbox_record["sandbox_dir"],
        "file_count": sandbox_record["file_count"],
        "materialized_at": sandbox_record["materialized_at"],
    }
    data["updated_at"] = data["promoted_at"]
    _save(case_id, data)
    return data
