"""Resolve evidence paths inside the R2 sandbox."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cold_box_room.r1.hallway import require_room
from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.paths import case_sandbox_dir


def resolve_sandbox_input(case_id: str, input_relpath: str) -> Path:
    require_room(case_id, 2)
    sandbox = case_sandbox_dir(case_id).resolve()
    if not sandbox.is_dir():
        raise ToolExecutionError(
            f"No R2 sandbox for {case_id!r} — promote from R1 first."
        )

    rel = input_relpath.replace("\\", "/").lstrip("/")
    if not rel or rel == ".":
        raise ToolExecutionError("input_relpath must name a file inside the sandbox")
    target = (sandbox / rel).resolve()
    try:
        target.relative_to(sandbox)
    except ValueError as exc:
        raise ToolExecutionError(
            f"input_relpath escapes sandbox: {input_relpath!r}"
        ) from exc
    if not target.is_file():
        raise ToolExecutionError(f"Sandbox input not found: {input_relpath!r}")
    return target


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
