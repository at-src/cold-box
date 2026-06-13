"""Guards — no writes on sealed R1 staging evidence."""

from __future__ import annotations

from pathlib import Path

from cold_box_room.r1.paths import StagingError, get_staging_root


class TouchForbiddenError(StagingError):
    """Direct access to sealed evidence — use staging read channel only."""


def assert_not_staging_write(path: str | Path, mode: str) -> None:
    if not any(ch in mode for ch in ("w", "a", "x", "+")):
        return

    root = get_staging_root().resolve()
    target = Path(path).expanduser().resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return

    raise TouchForbiddenError(
        f"Write forbidden on R1 staging area: mode={mode!r} path={target}"
    )
