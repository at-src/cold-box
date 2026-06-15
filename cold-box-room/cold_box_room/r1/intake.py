"""Intake — place raw evidence in R1 staging and seal."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.evidence import resolve_evidence_sources
from cold_box_room.r1.hallway import init_hallway
from cold_box_room.r1.manifest import build_manifest, manifest_digest
from cold_box_room.r1.paths import StagingError, case_records_dir, case_staging_dir, get_staging_root
from cold_box_room.r1.seal import is_sealed, require_unsealed, seal_case, strict_mode_enabled


def _stage_sources(
    staging: Path,
    sources: list[Path],
    *,
    link_only: bool,
) -> list[str]:
    """Copy or symlink each resolved source into staging; return basenames staged."""
    staged: list[str] = []
    for src in sources:
        dest = staging / src.name
        if dest.exists():
            staged.append(dest.name)
            continue
        if link_only:
            dest.symlink_to(src, target_is_directory=src.is_dir())
        else:
            shutil.copy2(src, dest)
        staged.append(dest.name)
    return staged


def list_staging_cases() -> list[str]:
    root = get_staging_root()
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
    """Copy raw upload into R1 staging, manifest, seal, init hallway at room 1."""
    require_unsealed(case_id)
    staging = case_staging_dir(case_id)

    if link_only and strict_mode_enabled():
        raise StagingError(
            "Symlink intake disabled in strict mode (COLD_BOX_ROOM_STRICT=1). "
            "Copy into R1 staging instead."
        )

    if source is not None:
        if staging.exists() and any(staging.iterdir()):
            raise StagingError(f"R1 staging already has material: {staging}")
        staging.mkdir(parents=True, exist_ok=True)
        sources = resolve_evidence_sources(source)
        _stage_sources(staging, sources, link_only=link_only)
    else:
        staging.mkdir(parents=True, exist_ok=True)
        if not any(staging.iterdir()):
            raise StagingError(
                f"No evidence in R1 staging for {case_id!r}. "
                f"Place files under: {staging}"
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
        "staging_dir": str(staging.resolve()),
        "source": str(source.resolve()) if source else None,
        "link_only": link_only,
        "intake_mode": "symlink" if link_only else "copy",
        "staged_files": [row["path"] for row in manifest.get("files") or []],
        "file_count": manifest["file_count"],
        "manifest_digest": digest,
        "manifest_path": str(manifest_path),
        "status": "sealed",
        "seal": seal_record,
        "hallway": hallway,
        "read_channel": "cold_box_room.r1.staging_read.open_staging_read",
    }
    (records / "intake.json").write_text(json.dumps(intake_record, indent=2), encoding="utf-8")
    return intake_record
