"""Hallway state — which room the case is in."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cold_box_room.r1.checkpoint import r1_checkpoint, require_r1_checkpoint
from cold_box_room.r1.paths import StagingError, hallway_state_path

ROOM_1 = "1"
ROOM_A = "A"
ROOM_2 = "2"
ROOM_B = "B"
ROOM_3 = "3"


def normalize_room(room: str | int) -> str:
    label = str(room).strip().upper()
    if label in {ROOM_1, ROOM_A, ROOM_2, ROOM_B, ROOM_3}:
        return label
    raise StagingError(f"Invalid room label: {room!r}")


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
        "room": ROOM_1,
        "r1_checkpoint": None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save(case_id, data)
    return data


def current_room(case_id: str) -> str:
    return normalize_room(_load(case_id).get("room", ROOM_1))


def require_room(case_id: str, room: str | int) -> None:
    expected = normalize_room(room)
    actual = current_room(case_id)
    if actual != expected:
        raise StagingError(
            f"Case {case_id!r} is in room {actual}, required room {expected}"
        )


def require_room_in(case_id: str, rooms: set[str | int]) -> None:
    allowed = {normalize_room(room) for room in rooms}
    actual = current_room(case_id)
    if actual not in allowed:
        raise StagingError(
            f"Case {case_id!r} is in room {actual}, required one of {sorted(allowed)}"
        )


def record_r1_check(case_id: str) -> dict[str, Any]:
    check = r1_checkpoint(case_id)
    data = _load(case_id)
    data["r1_checkpoint"] = check
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save(case_id, data)
    return check


def promote_to_room_a(case_id: str) -> dict[str, Any]:
    """R1 checkpoint passed → Room A (extraction planning; sandbox not copied yet)."""
    require_room(case_id, ROOM_1)
    require_r1_checkpoint(case_id)
    check = record_r1_check(case_id)

    data = _load(case_id)
    data["room"] = ROOM_A
    data["promoted_to_room_a_at"] = datetime.now(timezone.utc).isoformat()
    data["r1_checkpoint"] = check
    data["updated_at"] = data["promoted_to_room_a_at"]
    _save(case_id, data)
    return data


def promote_to_room2(case_id: str) -> dict[str, Any]:
    """Room A gate open → copy R1 evidence to R2 sandbox."""
    from cold_box_room.room_a import room_a_checkpoint

    require_room(case_id, ROOM_A)
    room_a = room_a_checkpoint(case_id)
    if not room_a["ready_for_room2"]:
        reasons = ", ".join(room_a["blocked_reasons"]) or "Room A gate closed"
        raise StagingError(f"Room A checkpoint failed: {reasons}")

    from cold_box_room.r2.sandbox import materialize_sandbox

    sandbox_record = materialize_sandbox(case_id)

    data = _load(case_id)
    data["room"] = ROOM_2
    data["promoted_at"] = datetime.now(timezone.utc).isoformat()
    data["room_a_checkpoint"] = room_a
    data["r2_sandbox"] = {
        "sandbox_dir": sandbox_record["sandbox_dir"],
        "file_count": sandbox_record["file_count"],
        "materialized_at": sandbox_record["materialized_at"],
    }
    data["updated_at"] = data["promoted_at"]
    _save(case_id, data)
    return data


def promote_to_room_b(case_id: str) -> dict[str, Any]:
    """Layer 1 complete → Room B entrance (analysis planning — not implemented yet)."""
    from cold_box_room.r2.checkpoint import r2_layer1_checkpoint

    require_room(case_id, ROOM_2)
    check = r2_layer1_checkpoint(case_id)
    if not check["ready_for_room_b"]:
        reasons = ", ".join(check["blocked_reasons"]) or "Layer 1 checkpoint failed"
        raise StagingError(f"Layer 1 checkpoint failed: {reasons}")

    data = _load(case_id)
    data["room"] = ROOM_B
    data["promoted_to_room_b_at"] = datetime.now(timezone.utc).isoformat()
    data["layer1_checkpoint"] = check
    data["updated_at"] = data["promoted_to_room_b_at"]
    _save(case_id, data)
    return data


def promote_to_room3(case_id: str) -> dict[str, Any]:
    """Room B gate open → Room 3 (Layer 2 analysis execution — not implemented yet)."""
    from cold_box_room.room_b import room_b_checkpoint

    require_room(case_id, ROOM_B)
    check = room_b_checkpoint(case_id)
    if not check["ready_for_room3"]:
        reasons = ", ".join(check["blocked_reasons"]) or "Room B checkpoint failed"
        raise StagingError(f"Room B checkpoint failed: {reasons}")

    data = _load(case_id)
    data["room"] = ROOM_3
    data["promoted_to_room3_at"] = datetime.now(timezone.utc).isoformat()
    data["room_b_checkpoint"] = check
    data["updated_at"] = data["promoted_to_room3_at"]
    _save(case_id, data)
    return data
