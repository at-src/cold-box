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
    """R1 checkpoint passed → Room A; sandbox materialized now so agent can see evidence."""
    require_room(case_id, ROOM_1)
    require_r1_checkpoint(case_id)
    check = record_r1_check(case_id)

    from cold_box_room.r2.sandbox import materialize_sandbox

    sandbox_record = materialize_sandbox(case_id)

    data = _load(case_id)
    data["room"] = ROOM_A
    data["promoted_to_room_a_at"] = datetime.now(timezone.utc).isoformat()
    data["r1_checkpoint"] = check
    data["r2_sandbox"] = {
        "sandbox_dir": sandbox_record["sandbox_dir"],
        "file_count": sandbox_record["file_count"],
        "materialized_at": sandbox_record["materialized_at"],
    }
    data["updated_at"] = data["promoted_to_room_a_at"]
    _save(case_id, data)
    return data


def promote_to_room2(case_id: str) -> dict[str, Any]:
    """Room A gate open → Room 2 (sandbox already materialized in Room A)."""
    from cold_box_room.room_a import room_a_checkpoint
    from cold_box_room.r2.sandbox import load_sandbox_record

    require_room(case_id, ROOM_A)
    room_a = room_a_checkpoint(case_id)
    if not room_a["ready_for_room2"]:
        reasons = ", ".join(room_a["blocked_reasons"]) or "Room A gate closed"
        raise StagingError(f"Room A checkpoint failed: {reasons}")

    sandbox_record = load_sandbox_record(case_id)

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
    """Room B gate open → Room 3 (Layer 2 analysis execution)."""
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


def unlocked_rooms(case_id: str) -> set[str]:
    """Rooms the case may return to after forward promotion (Room 1 is never unlocked)."""
    data = _load(case_id)
    unlocked: set[str] = set()
    if data.get("promoted_to_room_a_at"):
        unlocked.add(ROOM_A)
    if data.get("promoted_at"):
        unlocked.add(ROOM_2)
    if data.get("promoted_to_room_b_at"):
        unlocked.add(ROOM_B)
    if data.get("promoted_to_room3_at"):
        unlocked.add(ROOM_3)
    return unlocked


def list_room_revisits(case_id: str) -> list[dict[str, Any]]:
    data = _load(case_id)
    return list(data.get("room_revisits") or [])


def return_to_room(case_id: str, room: str | int, *, reason: str) -> dict[str, Any]:
    """Move case back to an earlier unlocked room to fix a mistake."""
    target = normalize_room(room)
    if target == ROOM_1:
        raise StagingError(
            "Room 1 is locked — sealed R1 evidence must not be revisited by the agent. "
            "Use return_to_room to Room A, 2, or B instead."
        )
    current = current_room(case_id)
    allowed = unlocked_rooms(case_id)
    if target not in allowed:
        raise StagingError(
            f"Room {target!r} is not unlocked for case {case_id!r} "
            f"(unlocked: {sorted(allowed)})"
        )
    if not reason.strip():
        raise StagingError("return_to_room requires a non-empty reason describing the mistake")

    data = _load(case_id)
    revisits = list(data.get("room_revisits") or [])
    revisits.append(
        {
            "from_room": current,
            "to_room": target,
            "reason": reason.strip(),
            "at": datetime.now(timezone.utc).isoformat(),
        }
    )
    data["room"] = target
    data["room_revisits"] = revisits
    data["updated_at"] = revisits[-1]["at"]
    _save(case_id, data)
    return {
        "ok": True,
        "case_id": case_id,
        "room": target,
        "from_room": current,
        "reason": reason.strip(),
        "unlocked_rooms": sorted(allowed),
    }
