"""SHA-256 manifest before seal; staging read after seal."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.paths import case_staging_dir, resolve_in_staging
from cold_box_room.r1.seal import is_sealed
from cold_box_room.r1.staging_read import StagingReader


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(case_id: str, *, relpath: str = ".") -> dict[str, Any]:
    staging = case_staging_dir(case_id)

    if is_sealed(case_id):
        reader = StagingReader(case_id)
        entries: list[dict[str, Any]] = []
        for rel, size in reader.iter_files():
            entries.append(
                {
                    "path": rel,
                    "size": size,
                    "sha256": reader.sha256(rel),
                    "via": StagingReader.CHANNEL,
                }
            )
        entries.sort(key=lambda item: item["path"])
        return {
            "case_id": case_id,
            "staging_dir": str(staging.resolve()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "algorithm": "sha256",
            "file_count": len(entries),
            "sealed": True,
            "read_channel": StagingReader.CHANNEL,
            "files": entries,
        }

    root = resolve_in_staging(case_id, relpath)
    if not root.is_dir():
        raise ValueError(f"Case material must be a directory: {root}")

    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            file_path = Path(dirpath) / name
            rel = file_path.relative_to(staging.resolve()).as_posix()
            stat = file_path.stat()
            entries.append(
                {"path": rel, "size": stat.st_size, "sha256": sha256_file(file_path)}
            )

    entries.sort(key=lambda item: item["path"])
    return {
        "case_id": case_id,
        "staging_dir": str(staging.resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "file_count": len(entries),
        "sealed": False,
        "files": entries,
    }


def manifest_digest(manifest: dict[str, Any]) -> str:
    lines = [f"{item['path']}|{item['sha256']}" for item in manifest.get("files", [])]
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()
