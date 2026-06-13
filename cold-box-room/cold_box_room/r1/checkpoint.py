"""Room 1 checkpoint — evidence present and not empty."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cold_box_room.r1.paths import StagingError
from cold_box_room.r1.seal import require_sealed
from cold_box_room.r1.staging_read import open_staging_read


def r1_checkpoint(case_id: str) -> dict[str, Any]:
    """Deterministic R1 gate: at least one non-empty file in sealed staging."""
    require_sealed(case_id)
    reader = open_staging_read(case_id)
    files = [(rel, size) for rel, size in reader.iter_files()]

    has_file = len(files) > 0
    non_empty = [rel for rel, size in files if size > 0]

    ok = has_file and len(non_empty) > 0
    reasons: list[str] = []
    if not has_file:
        reasons.append("no_file_in_staging")
    elif not non_empty:
        reasons.append("all_files_empty")

    return {
        "room": 1,
        "ok": ok,
        "file_count": len(files),
        "non_empty_files": non_empty,
        "reasons": reasons,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "promote_to_room": 2 if ok else None,
    }


def require_r1_checkpoint(case_id: str) -> None:
    result = r1_checkpoint(case_id)
    if not result["ok"]:
        raise StagingError(
            f"R1 checkpoint failed for {case_id!r}: {', '.join(result['reasons'])}"
        )
