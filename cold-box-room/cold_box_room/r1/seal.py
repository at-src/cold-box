"""Glass seal — read-only chmod on the staging table."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.paths import TableError, case_records_dir, case_slot

IMMUTABLE_FLAG = "+i"


def seal_record_path(case_id: str) -> Path:
    return case_records_dir(case_id) / "seal.json"


def is_sealed(case_id: str) -> bool:
    path = seal_record_path(case_id)
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return data.get("glass") == "locked"


def require_sealed(case_id: str) -> None:
    if not is_sealed(case_id):
        raise TableError(
            f"Case {case_id!r} is not sealed. Run intake — glass must be locked before R1 checkpoint."
        )


def require_unsealed(case_id: str) -> None:
    if is_sealed(case_id):
        raise TableError(f"Case {case_id!r} is sealed. No writes to the table are permitted.")


def _apply_readonly_chmod(slot: Path) -> None:
    for root, dirnames, filenames in os.walk(slot, topdown=False):
        root_path = Path(root)
        for name in filenames:
            path = root_path / name
            mode = path.stat().st_mode
            path.chmod(
                mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
                | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
            )
        for name in dirnames:
            path = root_path / name
            mode = path.stat().st_mode
            path.chmod(
                mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
                | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
            )
    slot_mode = slot.stat().st_mode
    slot.chmod(
        slot_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
        | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    )


def _apply_immutable(slot: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"requested": True, "applied": False, "paths": []}
    try:
        proc = subprocess.run(
            ["chattr", "-R", IMMUTABLE_FLAG, str(slot)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        result["error"] = f"chattr unavailable: {exc}"
        return result

    if proc.returncode != 0:
        result["error"] = (proc.stderr or proc.stdout or "chattr failed").strip()
        return result

    result["applied"] = True
    result["paths"] = [str(slot.resolve())]
    return result


def strict_mode_enabled() -> bool:
    raw = os.environ.get("COLD_BOX_ROOM_STRICT", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def seal_case(case_id: str, *, manifest_digest: str) -> dict[str, Any]:
    require_unsealed(case_id)
    slot = case_slot(case_id)
    if not slot.is_dir() or not any(slot.iterdir()):
        raise TableError(f"Nothing on table to seal for {case_id!r}")

    _apply_readonly_chmod(slot)
    immutable = _apply_immutable(slot)

    layers = ["chmod_readonly"]
    if immutable.get("applied"):
        layers.append("chattr_immutable")

    record = {
        "case_id": case_id,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "glass": "locked",
        "room": 1,
        "table_slot": str(slot.resolve()),
        "manifest_digest": manifest_digest,
        "layers": layers,
        "immutable": immutable,
        "machine_channel": "cold_box_room.r1.viewport.TableViewport",
    }
    seal_record_path(case_id).write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record
