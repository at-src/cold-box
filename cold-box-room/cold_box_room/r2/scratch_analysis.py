"""Run allowlisted parsers against files in case scratch."""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.hallway import require_room
from cold_box_room.r2.audit import append_audit, next_audit_id
from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.output_files import (
    describe_output_file,
    read_text_preview,
    scratch_dir,
    scratch_relpath as scratch_file_relpath,
    stream_pipe_to_file,
)
from cold_box_room.r2.security import sanitize_extra_args
from cold_box_room.r2.tool_log import append_tool_log

ALLOWED_BINARIES = frozenset({"grep", "strings", "file", "sqlite3", "head", "tail", "wc", "identify"})
DEFAULT_TIMEOUT = 120


def resolve_scratch_path(case_id: str, scratch_relpath: str) -> Path:
    require_room(case_id, 2)
    root = scratch_dir(case_id).resolve()
    raw = scratch_relpath.strip()
    if Path(raw).is_absolute():
        candidate = Path(raw).resolve()
    else:
        candidate = (root / raw.lstrip("/")).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ToolExecutionError(
            f"Scratch path must stay under case scratch; got {scratch_relpath!r}"
        ) from exc
    if not candidate.is_file():
        raise ToolExecutionError(f"Scratch file not found: {scratch_relpath!r}")
    return candidate


def run_scratch_analysis(
    *,
    case_id: str,
    binary: str,
    scratch_relpath: str,
    args: list[str] | None,
    purpose: str,
    why: str,
    timeout: int | None = None,
) -> dict[str, Any]:
    name = binary.strip().lower()
    if name not in ALLOWED_BINARIES:
        raise ToolExecutionError(
            f"Binary {binary!r} not allowed on scratch; use one of {sorted(ALLOWED_BINARIES)}"
        )
    resolved_bin = shutil.which(name)
    if not resolved_bin:
        raise ToolExecutionError(f"{name} not installed on PATH")

    target = resolve_scratch_path(case_id, scratch_relpath)
    extra = sanitize_extra_args(list(args or []), tool_name=name)
    cmd = [resolved_bin, *extra, str(target)]

    audit_id = next_audit_id()
    scratch = scratch_dir(case_id)
    out_root = scratch / f"{audit_id}_scratch_{name}"
    out_root.mkdir(parents=True, exist_ok=True)
    stdout_path = out_root / "stdout.txt"

    start = time.monotonic()
    truncated = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(scratch),
            shell=False,
        )
        assert proc.stdout is not None
        _, truncated = stream_pipe_to_file(proc.stdout, stdout_path)
        if truncated and proc.poll() is None:
            proc.kill()
        stderr = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", errors="replace")
        proc.wait(timeout=timeout or DEFAULT_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        append_audit(
            case_id=case_id,
            audit_id=audit_id,
            tool_id="SCRATCH",
            tool_name=name,
            purpose=purpose,
            why=why,
            command=cmd,
            input_relpath=scratch_relpath,
            input_sha256="",
            exit_code=-1,
            elapsed_ms=elapsed_ms,
            error=f"Timed out after {timeout or DEFAULT_TIMEOUT}s",
        )
        append_tool_log(
            case_id=case_id,
            audit_id=audit_id,
            tool_id="SCRATCH",
            tool_name=name,
            purpose=purpose,
            command=cmd,
            input_relpath=scratch_relpath,
            exit_code=-1,
            error=f"Timed out after {timeout or DEFAULT_TIMEOUT}s",
        )
        raise ToolExecutionError(f"Timed out after {timeout or DEFAULT_TIMEOUT}s") from exc

    elapsed_ms = (time.monotonic() - start) * 1000
    output_meta = describe_output_file(stdout_path, case_id=case_id)
    audit_preview = str(
        output_meta.get("stdout_preview") or read_text_preview(stdout_path)
    )[:2000]

    out_root.joinpath("run.meta.txt").write_text(
        f"audit_id={audit_id}\nts={datetime.now(timezone.utc).isoformat()}\n",
        encoding="utf-8",
    )
    output_files = [str(stdout_path), str(out_root / "run.meta.txt")]
    if stderr:
        err_path = out_root / "stderr.txt"
        err_path.write_text(stderr, encoding="utf-8")
        output_files.append(str(err_path))

    append_audit(
        case_id=case_id,
        audit_id=audit_id,
        tool_id="SCRATCH",
        tool_name=name,
        purpose=purpose,
        why=why,
        command=cmd,
        input_relpath=scratch_relpath,
        input_sha256="",
        exit_code=proc.returncode,
        elapsed_ms=elapsed_ms,
        output_files=output_files,
        stdout_preview=audit_preview,
    )
    append_tool_log(
        case_id=case_id,
        audit_id=audit_id,
        tool_id="SCRATCH",
        tool_name=name,
        purpose=purpose,
        command=cmd,
        input_relpath=scratch_relpath,
        exit_code=proc.returncode,
        scratch_refs=[scratch_file_relpath(case_id, stdout_path)],
        stdout_preview=audit_preview,
    )

    return {
        "ok": proc.returncode == 0,
        "audit_id": audit_id,
        "tool_name": name,
        "case_id": case_id,
        "exit_code": proc.returncode,
        "stdout_preview": audit_preview,
        "preview": output_meta.get("preview"),
        "stderr_preview": stderr[:400],
        "truncated": truncated,
        **output_meta,
    }
