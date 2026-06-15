"""Helpers for mactime bodyfile resolution in harness and skill scripts."""

from __future__ import annotations

import os
from pathlib import Path

EVIDENCE_SUFFIXES = frozenset(
    {".e01", ".ewf", ".ex01", ".dd", ".raw", ".aff", ".001", ".bin", ".img"}
)
MAX_BODYFILE_BYTES = int(os.environ.get("COLD_BOX_MAX_BODYFILE_BYTES", str(512 * 1024 * 1024)))


class MactimeBodyfileError(ValueError):
    """Invalid or missing TSK bodyfile for mactime."""


def looks_like_disk_image(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in EVIDENCE_SUFFIXES:
        return True
    if name.endswith(".e01") or name.endswith(".001"):
        return True
    return False


def is_valid_tsk_bodyfile(path: Path) -> bool:
    if not path.is_file():
        return False
    if looks_like_disk_image(path):
        return False
    size = path.stat().st_size
    if size == 0 or size > MAX_BODYFILE_BYTES:
        return False
    sample = path.read_bytes()[:8192].decode("utf-8", errors="replace")
    for line in sample.splitlines()[:25]:
        stripped = line.strip()
        if stripped and "|" in stripped:
            return True
    return False


def validate_mactime_bodyfile(path: Path) -> None:
    if looks_like_disk_image(path):
        raise MactimeBodyfileError(
            "mactime -b must be a TSK bodyfile from `fls -m`, not a disk image"
        )
    if not is_valid_tsk_bodyfile(path):
        raise MactimeBodyfileError(
            "mactime -b bodyfile must be non-empty pipe-delimited output from `fls -m` "
            "(generate with e.g. fls -r -m / -o 63 <image>)"
        )


def mactime_bodyfile_from_extra(
    extra_args: list[str],
    *,
    scratch_root: Path,
) -> tuple[Path | None, list[str]]:
    """Return scratch-resolved bodyfile path and remaining mactime flags."""
    remaining: list[str] = []
    bodyfile: Path | None = None
    i = 0
    while i < len(extra_args):
        arg = extra_args[i]
        if arg == "-b" and i + 1 < len(extra_args):
            candidate = Path(extra_args[i + 1])
            resolved = candidate.expanduser()
            if not resolved.is_absolute():
                resolved = (scratch_root / extra_args[i + 1].lstrip("/")).resolve()
            else:
                resolved = resolved.resolve()
            try:
                resolved.relative_to(scratch_root.resolve())
            except ValueError:
                remaining.append(arg)
                i += 1
                continue
            if resolved.is_file():
                validate_mactime_bodyfile(resolved)
                bodyfile = resolved
                i += 2
                continue
        remaining.append(arg)
        i += 1
    return bodyfile, remaining
