"""Operation table paths — Room 1 evidence lives here only."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

TABLE_ROOT_ENV = "COLD_BOX_ROOM_TABLE"
RECORDS_ROOT_ENV = "COLD_BOX_ROOM_RECORDS"


class TableError(ValueError):
    """Invalid table configuration or path."""


def get_table_root() -> Path:
    raw = os.environ.get(TABLE_ROOT_ENV, str(REPO_ROOT / "operation-table")).strip()
    if not raw:
        raise TableError(f"{TABLE_ROOT_ENV} is empty")
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_records_root() -> Path:
    raw = os.environ.get(RECORDS_ROOT_ENV, str(REPO_ROOT / "records")).strip()
    if not raw:
        raise TableError(f"{RECORDS_ROOT_ENV} is empty")
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def case_slot(case_id: str) -> Path:
    safe = _validate_case_id(case_id)
    return get_table_root() / safe


def case_records_dir(case_id: str) -> Path:
    safe = _validate_case_id(case_id)
    path = get_records_root() / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def hallway_state_path(case_id: str) -> Path:
    return case_records_dir(case_id) / "hallway.json"


def _validate_case_id(case_id: str) -> str:
    case_id = case_id.strip()
    if not case_id or len(case_id) > 128:
        raise TableError(f"Invalid case_id: {case_id!r}")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise TableError(f"Invalid case_id: {case_id!r}")
    return case_id


def resolve_on_table(case_id: str, relpath: str = ".") -> Path:
    """Resolve path under case slot before seal only."""
    from cold_box_room.r1.guard import TouchForbiddenError
    from cold_box_room.r1.seal import is_sealed

    if is_sealed(case_id):
        raise TouchForbiddenError(
            f"Direct path access blocked — case {case_id!r} is sealed. "
            "Use open_viewport(case_id)."
        )

    slot = case_slot(case_id)
    if not slot.is_dir():
        raise TableError(f"No material on table for case {case_id!r}: {slot}")

    rel = relpath.replace("\\", "/").lstrip("/")
    target = slot.resolve() if rel in {".", ""} else (slot / rel).resolve()

    try:
        target.relative_to(slot.resolve())
    except ValueError as exc:
        raise TableError(f"Path escapes operation table: {target}") from exc

    if not target.exists():
        raise TableError(f"Path does not exist on table: {target}")
    return target
