"""R1 staging paths — raw evidence lives here only."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

STAGING_ROOT_ENV = "COLD_BOX_R1_STAGING"
RECORDS_ROOT_ENV = "COLD_BOX_ROOM_RECORDS"


class StagingError(ValueError):
    """Invalid staging configuration or path."""


def get_staging_root() -> Path:
    raw = os.environ.get(STAGING_ROOT_ENV, str(REPO_ROOT / "r1-staging")).strip()
    if not raw:
        raise StagingError(f"{STAGING_ROOT_ENV} is empty")
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_records_root() -> Path:
    raw = os.environ.get(RECORDS_ROOT_ENV, str(REPO_ROOT / "records")).strip()
    if not raw:
        raise StagingError(f"{RECORDS_ROOT_ENV} is empty")
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def case_staging_dir(case_id: str) -> Path:
    safe = _validate_case_id(case_id)
    return get_staging_root() / safe


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
        raise StagingError(f"Invalid case_id: {case_id!r}")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise StagingError(f"Invalid case_id: {case_id!r}")
    return case_id


def resolve_in_staging(case_id: str, relpath: str = ".") -> Path:
    """Resolve path under case staging dir before seal only."""
    from cold_box_room.r1.guard import TouchForbiddenError
    from cold_box_room.r1.seal import is_sealed

    if is_sealed(case_id):
        raise TouchForbiddenError(
            f"Direct path access blocked — case {case_id!r} is sealed. "
            "Use open_staging_read(case_id)."
        )

    staging = case_staging_dir(case_id)
    if not staging.is_dir():
        raise StagingError(f"No evidence in R1 staging for case {case_id!r}: {staging}")

    rel = relpath.replace("\\", "/").lstrip("/")
    target = staging.resolve() if rel in {".", ""} else (staging / rel).resolve()

    try:
        target.relative_to(staging.resolve())
    except ValueError as exc:
        raise StagingError(f"Path escapes R1 staging area: {target}") from exc

    if not target.exists():
        raise StagingError(f"Path does not exist in R1 staging: {target}")
    return target
