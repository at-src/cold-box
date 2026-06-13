"""R2 sandbox paths — isolated workspace for evidence examination."""

from __future__ import annotations

import os
from pathlib import Path

from cold_box_room.r1.paths import REPO_ROOT, StagingError, _validate_case_id

SANDBOX_ROOT_ENV = "COLD_BOX_R2_SANDBOX"


class SandboxError(StagingError):
    """Invalid R2 sandbox configuration or state."""


def get_sandbox_root() -> Path:
    raw = os.environ.get(SANDBOX_ROOT_ENV, str(REPO_ROOT / "r2-sandbox")).strip()
    if not raw:
        raise SandboxError(f"{SANDBOX_ROOT_ENV} is empty")
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def case_sandbox_dir(case_id: str) -> Path:
    safe = _validate_case_id(case_id)
    return get_sandbox_root() / safe


def sandbox_record_path(case_id: str) -> Path:
    from cold_box_room.r1.paths import case_records_dir

    return case_records_dir(case_id) / "r2_sandbox.json"
