"""Resolve evidence paths inside the R2 sandbox."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cold_box_room.r1.hallway import ROOM_2, ROOM_3, require_room, require_room_in
from cold_box_room.r2.skill_harness import skill_harness_active
from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.paths import case_sandbox_dir


def _require_sandbox_room(case_id: str) -> None:
    if skill_harness_active():
        require_room_in(case_id, {ROOM_2, ROOM_3})
    else:
        require_room(case_id, ROOM_2)


def resolve_sandbox_input_for_skill(case_id: str, input_relpath: str) -> Path:
    """Resolve sandbox path for Room 3 skill scripts (also valid in Room 2 during harness)."""
    require_room_in(case_id, {ROOM_2, ROOM_3})
    return _resolve_sandbox_path(case_id, input_relpath)


def resolve_sandbox_input(case_id: str, input_relpath: str) -> Path:
    _require_sandbox_room(case_id)
    return _resolve_sandbox_path(case_id, input_relpath)


def _resolve_sandbox_path(case_id: str, input_relpath: str) -> Path:
    sandbox = case_sandbox_dir(case_id).resolve()
    if not sandbox.is_dir():
        raise ToolExecutionError(
            f"No R2 sandbox for {case_id!r} — promote from R1 first."
        )

    rel = input_relpath.replace("\\", "/").strip().lstrip("/")
    if not rel or rel == ".":
        raise ToolExecutionError("input_relpath must name a file inside the sandbox")
    if ".." in Path(rel).parts:
        raise ToolExecutionError(f"input_relpath escapes sandbox: {input_relpath!r}")
    target = sandbox / rel
    try:
        target.relative_to(sandbox)
    except ValueError as exc:
        raise ToolExecutionError(
            f"input_relpath escapes sandbox: {input_relpath!r}"
        ) from exc
    if not target.is_file() and not target.is_symlink():
        raise ToolExecutionError(f"Sandbox input not found: {input_relpath!r}")
    if not target.exists():
        raise ToolExecutionError(f"Sandbox input not found: {input_relpath!r}")
    return target


def sha256_file(path: Path) -> str:
    if os.environ.get("COLD_BOX_R1_STAT_ONLY", "").strip() in {"1", "true", "yes"}:
        st = path.stat()
        return f"stat-only:{st.st_size}:{st.st_mtime_ns}"
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
