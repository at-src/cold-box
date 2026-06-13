"""Intake — place raw evidence on the table and lock the glass (Room 1)."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.hallway import init_hallway
from cold_box_room.r1.manifest import build_manifest, manifest_digest
from cold_box_room.r1.paths import TableError, case_records_dir, case_slot, get_table_root
from cold_box_room.r1.seal import is_sealed, require_unsealed, seal_case, strict_mode_enabled


def list_table_cases() -> list[str]:
    root = get_table_root()
    return sorted(
        child.name
        for child in root.iterdir()
        if child.is_dir() and not child.name.startswith(".")
    )


def intake_case(
    case_id: str,
    *,
    source: Path | None = None,
    link_only: bool = False,
) -> dict[str, Any]:
    """Copy raw upload onto table, manifest, seal glass, init hallway at Room 1."""
    require_unsealed(case_id)
    slot = case_slot(case_id)

    if link_only and strict_mode_enabled():
        raise TableError(
            "Symlink intake disabled in strict mode (COLD_BOX_ROOM_STRICT=1). "
            "Copy onto the table instead."
        )

    if source is not None:
        src = source.expanduser().resolve()
        if not src.exists():
            raise TableError(f"Source does not exist: {src}")
        if slot.exists() and any(slot.iterdir()):
            raise TableError(f"Table slot already has material: {slot}")
        slot.mkdir(parents=True, exist_ok=True)
        if link_only:
            dest = slot / src.name
            if not dest.exists():
                dest.symlink_to(src, target_is_directory=src.is_dir())
        elif src.is_dir():
            for item in src.iterdir():
                d = slot / item.name
                if item.is_dir():
                    shutil.copytree(item, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, d)
        else:
            shutil.copy2(src, slot / src.name)
    else:
        slot.mkdir(parents=True, exist_ok=True)
        if not any(slot.iterdir()):
            raise TableError(
                f"No material on operation table for {case_id!r}. "
                f"Place files under: {slot}"
            )

    manifest = build_manifest(case_id)
    digest = manifest_digest(manifest)
    records = case_records_dir(case_id)
    manifest_path = records / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    seal_record = seal_case(case_id, manifest_digest=digest)
    hallway = init_hallway(case_id)

    intake_record = {
        "case_id": case_id,
        "room": 1,
        "intake_at": datetime.now(timezone.utc).isoformat(),
        "table_slot": str(slot.resolve()),
        "source": str(source.resolve()) if source else None,
        "link_only": link_only,
        "intake_mode": "symlink" if link_only else "copy",
        "file_count": manifest["file_count"],
        "manifest_digest": digest,
        "manifest_path": str(manifest_path),
        "status": "sealed_on_table",
        "glass": seal_record,
        "hallway": hallway,
        "machine_read_path": "cold_box_room.r1.viewport.open_viewport",
    }
    (records / "intake.json").write_text(json.dumps(intake_record, indent=2), encoding="utf-8")
    return intake_record
