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


def stat_only_enabled() -> bool:
    """When set, manifest uses stat metadata only — no file content reads."""
    raw = os.environ.get("COLD_BOX_R1_STAT_ONLY", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def stat_fingerprint(st: os.stat_result) -> str:
    return f"stat:{st.st_size}:{st.st_mtime_ns}:{st.st_ino}"


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
            item: dict[str, Any] = {
                "path": rel,
                "size": size,
                "via": StagingReader.CHANNEL,
            }
            if stat_only_enabled():
                item["sha256"] = None
                item["fingerprint"] = stat_fingerprint(reader.abs_path(rel).lstat())
            else:
                item["sha256"] = reader.sha256(rel)
            entries.append(item)
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
            st = file_path.stat()
            item = {"path": rel, "size": st.st_size}
            if stat_only_enabled():
                item["sha256"] = None
                item["fingerprint"] = stat_fingerprint(st)
            else:
                item["sha256"] = sha256_file(file_path)
            entries.append(item)

    entries.sort(key=lambda item: item["path"])
    return {
        "case_id": case_id,
        "staging_dir": str(staging.resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "file_count": len(entries),
        "sealed": False,
        "stat_only": stat_only_enabled(),
        "files": entries,
    }


def manifest_digest(manifest: dict[str, Any]) -> str:
    lines: list[str] = []
    for item in manifest.get("files", []):
        if item.get("fingerprint"):
            lines.append(f"{item['path']}|{item['fingerprint']}")
        else:
            lines.append(f"{item['path']}|{item['sha256']}")
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()
