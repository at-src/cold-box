"""Read-only evidence path guard."""

from __future__ import annotations

import os
from pathlib import Path

EVIDENCE_ROOT_ENV = "EVIDENCE_ROOT"


class EvidencePathError(ValueError):
    """Raised when a path violates evidence read-only rules."""


def get_evidence_root() -> Path:
    raw = os.environ.get(EVIDENCE_ROOT_ENV, "/evidence").strip()
    if not raw:
        raise EvidencePathError(f"{EVIDENCE_ROOT_ENV} is empty")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise EvidencePathError(f"Evidence root does not exist: {root}")
    return root


def resolve_read_path(path: str | Path, *, evidence_root: Path | None = None) -> Path:
    """Resolve path and ensure it stays under the evidence root (read-only zone)."""
    root = evidence_root or get_evidence_root()
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = (root / candidate).resolve()
    else:
        candidate = candidate.resolve()

    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise EvidencePathError(
            f"Path outside evidence root: {candidate} (root={root_resolved})"
        ) from exc

    if not candidate.exists():
        raise EvidencePathError(f"Path does not exist: {candidate}")
    return candidate


def assert_not_evidence_write(path: str | Path, mode: str) -> None:
    """Block write/create/truncate modes for paths under EVIDENCE_ROOT."""
    if not any(ch in mode for ch in ("w", "a", "x", "+")):
        return

    root = get_evidence_root()
    target = Path(path).expanduser().resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return
    raise EvidencePathError(
        f"Write mode {mode!r} blocked under evidence root: {target}"
    )
