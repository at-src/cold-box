"""R2 sandbox — copy sealed R1 evidence into an isolated workspace."""

from __future__ import annotations

import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.staging_read import open_staging_read
from cold_box_room.r2.paths import SandboxError, case_sandbox_dir, sandbox_record_path


def _iter_sandbox_files(sandbox: Path) -> list[dict[str, Any]]:
    root = sandbox.resolve()
    entries: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            file_path = Path(dirpath) / name
            rel = file_path.relative_to(root).as_posix()
            entries.append({"path": rel, "size": file_path.stat().st_size})
    entries.sort(key=lambda item: item["path"])
    return entries


def list_sandbox_files(case_id: str) -> list[dict[str, Any]]:
    sandbox = case_sandbox_dir(case_id)
    if not sandbox.is_dir():
        return []
    return _iter_sandbox_files(sandbox)


def _make_sandbox_writable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(
        mode | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        if path.is_dir()
        else mode | stat.S_IWUSR
    )


def materialize_sandbox(case_id: str) -> dict[str, Any]:
    """Copy all sealed R1 evidence into the R2 sandbox for this case."""
    reader = open_staging_read(case_id)
    sandbox = case_sandbox_dir(case_id)
    if sandbox.exists():
        shutil.rmtree(sandbox)
    sandbox.mkdir(parents=True, exist_ok=True)

    copied: list[dict[str, Any]] = []
    for rel, size in reader.iter_files():
        src = reader.abs_path(rel)
        dest = sandbox / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            dest.symlink_to(src.resolve())
            copied.append({"path": rel, "size": size, "mode": "symlink"})
        else:
            shutil.copy2(src, dest, follow_symlinks=True)
            _make_sandbox_writable(dest)
            copied.append({"path": rel, "size": dest.stat().st_size, "mode": "copy"})

    _make_sandbox_writable(sandbox)

    if not copied:
        raise SandboxError(f"No evidence copied into R2 sandbox for {case_id!r}")

    record = {
        "case_id": case_id,
        "room": 2,
        "sandbox_dir": str(sandbox.resolve()),
        "source_channel": reader.CHANNEL,
        "file_count": len(copied),
        "files": copied,
        "materialized_at": datetime.now(timezone.utc).isoformat(),
    }
    sandbox_record_path(case_id).write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return record


def load_sandbox_record(case_id: str) -> dict[str, Any]:
    path = sandbox_record_path(case_id)
    if not path.is_file():
        raise SandboxError(
            f"No R2 sandbox record for {case_id!r} — promote from R1 first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def r2_status(case_id: str) -> dict[str, Any]:
    from cold_box_room.r1.hallway import require_room

    require_room(case_id, 2)
    record = load_sandbox_record(case_id)
    sandbox = case_sandbox_dir(case_id)
    live_files = list_sandbox_files(case_id)
    non_empty = [item["path"] for item in live_files if item["size"] > 0]
    return {
        "case_id": case_id,
        "room": 2,
        "sandbox_dir": str(sandbox.resolve()),
        "file_count": len(live_files),
        "non_empty_files": non_empty,
        "materialized_at": record.get("materialized_at"),
        "files": live_files,
    }
