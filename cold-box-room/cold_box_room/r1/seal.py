"""R1 seal — read-only chmod on staging evidence."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.paths import StagingError, case_records_dir, case_staging_dir

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
    return data.get("sealed") is True


def require_sealed(case_id: str) -> None:
    if not is_sealed(case_id):
        raise StagingError(
            f"Case {case_id!r} is not sealed. Run intake before R1 checkpoint."
        )


def require_unsealed(case_id: str) -> None:
    if is_sealed(case_id):
        raise StagingError(f"Case {case_id!r} is sealed. No writes to R1 staging.")


def _apply_readonly_chmod(staging: Path) -> None:
    for root, dirnames, filenames in os.walk(staging, topdown=False):
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
    staging_mode = staging.stat().st_mode
    staging.chmod(
        staging_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
        | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    )


def _apply_immutable(staging: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"requested": True, "applied": False, "paths": []}
    try:
        proc = subprocess.run(
            ["chattr", "-R", IMMUTABLE_FLAG, str(staging)],
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
    result["paths"] = [str(staging.resolve())]
    return result


def strict_mode_enabled() -> bool:
    raw = os.environ.get("COLD_BOX_ROOM_STRICT", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def seal_case(case_id: str, *, manifest_digest: str) -> dict[str, Any]:
    require_unsealed(case_id)
    staging = case_staging_dir(case_id)
    if not staging.is_dir() or not any(staging.iterdir()):
        raise StagingError(f"Nothing in R1 staging to seal for {case_id!r}")

    _apply_readonly_chmod(staging)
    immutable = _apply_immutable(staging)

    layers = ["chmod_readonly"]
    if immutable.get("applied"):
        layers.append("chattr_immutable")

    record = {
        "case_id": case_id,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "sealed": True,
        "room": 1,
        "staging_dir": str(staging.resolve()),
        "manifest_digest": manifest_digest,
        "layers": layers,
        "immutable": immutable,
        "read_channel": "cold_box_room.r1.staging_read.StagingReader",
    }
    seal_record_path(case_id).write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record
