"""Resolve evidence paths for R1 intake — directories, EWF segment chains."""

from __future__ import annotations

import re
from pathlib import Path

from cold_box_room.r1.paths import StagingError

_EWF_E01 = re.compile(r"^(?P<base>.+)\.(E01)$", re.IGNORECASE)
_EWF_SEGMENT = re.compile(r"^(?P<base>.+)\.(E(?P<num>\d+))$", re.IGNORECASE)


def expand_ewf_chain(path: Path) -> list[Path]:
    """If ``path`` is an E01 segment, include E02, E03, … siblings from the same directory."""
    resolved = path.expanduser().resolve()
    match = _EWF_E01.match(resolved.name)
    if not match:
        return [resolved]

    base = match.group("base")
    parent = resolved.parent
    chain = [resolved]
    for num in range(2, 100):
        segment = parent / f"{base}.E{num:02d}"
        if segment.is_file():
            chain.append(segment)
        else:
            break
    return chain


def list_directory_evidence(directory: Path) -> list[Path]:
    """All non-hidden items (files and subdirectories) in a directory, sorted by name."""
    resolved = directory.expanduser().resolve()
    if not resolved.is_dir():
        raise StagingError(f"Not a directory: {resolved}")
    items = sorted(
        (p for p in resolved.iterdir() if not p.name.startswith(".")),
        key=lambda p: p.name.lower(),
    )
    if not items:
        raise StagingError(f"No evidence in directory: {resolved}")
    return items


def resolve_evidence_sources(source: Path) -> list[Path]:
    """Expand a file or directory into the list of paths to stage in R1."""
    resolved = source.expanduser().resolve()
    if not resolved.exists():
        raise StagingError(f"Source does not exist: {resolved}")

    if resolved.is_dir():
        return list_directory_evidence(resolved)

    if not resolved.is_file():
        raise StagingError(f"Source is not a file or directory: {resolved}")

    return expand_ewf_chain(resolved)


def staging_names_from_manifest(manifest: dict) -> set[str]:
    return {str(row.get("path") or "") for row in manifest.get("files") or [] if row.get("path")}


def validate_benchmark_staging_scope(
    *,
    staged_files: set[str],
    benchmark: dict,
) -> dict:
    """Compare sealed staging manifest to benchmark ``required_staging_files``."""
    required = [str(name) for name in benchmark.get("required_staging_files") or [] if str(name).strip()]
    optional = [str(name) for name in benchmark.get("optional_staging_files") or [] if str(name).strip()]
    missing_required = sorted(name for name in required if name not in staged_files)
    missing_optional = sorted(name for name in optional if name not in staged_files)
    return {
        "scope_ok": not missing_required,
        "staged_file_count": len(staged_files),
        "staged_files": sorted(staged_files),
        "required_staging_files": required,
        "optional_staging_files": optional,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
    }
