"""Guards — no writes on the sealed operation table."""

from __future__ import annotations

from pathlib import Path

from cold_box_room.r1.paths import TableError, get_table_root
from cold_box_room.r1.seal import is_sealed


class TouchForbiddenError(TableError):
    """Direct contact with sealed evidence — use viewport only."""


def assert_not_table_write(path: str | Path, mode: str) -> None:
    if not any(ch in mode for ch in ("w", "a", "x", "+")):
        return

    root = get_table_root().resolve()
    target = Path(path).expanduser().resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return

    raise TouchForbiddenError(
        f"Write forbidden on operation table: mode={mode!r} path={target}"
    )
