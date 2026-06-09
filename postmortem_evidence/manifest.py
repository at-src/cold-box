"""SHA-256 evidence manifest."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from postmortem_evidence.guard import resolve_read_path


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    case_root: str | Path,
    *,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    """Build a SHA-256 manifest for all files under case_root."""
    resolved = resolve_read_path(case_root, evidence_root=evidence_root)
    if not resolved.is_dir():
        raise ValueError(f"Case root must be a directory: {resolved}")

    entries = []
    for dirpath, dirnames, filenames in os.walk(resolved):
        dirnames.sort()
        for name in sorted(filenames):
            file_path = Path(dirpath) / name
            rel = file_path.relative_to(resolved).as_posix()
            stat = file_path.stat()
            entries.append(
                {
                    "path": rel,
                    "size": stat.st_size,
                    "sha256": sha256_file(file_path),
                }
            )

    entries.sort(key=lambda item: item["path"])

    return {
        "case_root": str(resolved),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "file_count": len(entries),
        "files": entries,
    }


def manifest_digest(manifest: dict[str, Any]) -> str:
    """Stable digest over file hashes for quick comparison."""
    lines = [f"{item['path']}|{item['sha256']}" for item in manifest.get("files", [])]
    payload = "\n".join(sorted(lines)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
