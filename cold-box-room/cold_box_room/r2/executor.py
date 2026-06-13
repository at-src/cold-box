"""Run cataloged SIFT tools — R2 sandbox in, scratch out."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r2.audit import append_audit, next_audit_id
from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.output_files import (
    MAX_SCRATCH_FILE_BYTES,
    describe_output_file,
    read_text_preview,
    scratch_dir,
    scratch_relpath,
    stream_pipe_to_file,
)
from cold_box_room.r2.sandbox_input import resolve_sandbox_input, sha256_file
from cold_box_room.r2.security import is_denied, sanitize_extra_args, validate_output_args
from cold_box_room.r2.tool_log import append_tool_log
from cold_box_room.tools.models import ToolRecord
from cold_box_room.tools.registry import ToolCatalogError, get_tool

MAX_OUTPUT_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 600
ICAT_MAX_BYTES = int(os.environ.get("COLD_BOX_ICAT_MAX_BYTES", str(20 * 1024 * 1024)))
ICAT_ISTAT_TIMEOUT = int(os.environ.get("COLD_BOX_ICAT_ISTAT_TIMEOUT", "90"))
INODE_PLACEHOLDER = "@@"


def _read_pipe(pipe, chunks: list[bytes], limit: int, total: list[int]) -> None:
    while True:
        remaining = limit - total[0]
        if remaining <= 0:
            break
        data = pipe.read(min(65536, remaining))
        if not data:
            break
        chunks.append(data)
        total[0] += len(data)


def _execute(
    cmd: list[str],
    *,
    timeout: int,
    cwd: Path,
    stdout_file: Path | None = None,
) -> dict[str, Any]:
    start = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd),
        shell=False,
    )
    truncated = False
    if stdout_file is not None:
        assert proc.stdout is not None
        _, truncated = stream_pipe_to_file(
            proc.stdout,
            stdout_file,
            max_bytes=MAX_SCRATCH_FILE_BYTES,
        )
        if truncated and proc.poll() is None:
            proc.kill()
        stderr_chunks: list[bytes] = []
        if proc.stderr:
            stderr_chunks.append(proc.stderr.read(MAX_OUTPUT_BYTES // 4))
    else:
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        total = [0]
        stdout_thread = threading.Thread(
            target=_read_pipe,
            args=(proc.stdout, stdout_chunks, MAX_OUTPUT_BYTES, total),
        )
        stderr_thread = threading.Thread(
            target=_read_pipe,
            args=(proc.stderr, stderr_chunks, MAX_OUTPUT_BYTES // 4, total),
        )
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        truncated = total[0] >= MAX_OUTPUT_BYTES

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait(timeout=5)
        raise ToolExecutionError(f"Timed out after {timeout}s") from exc

    elapsed = time.monotonic() - start
    stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
    if stdout_file is not None:
        return {
            "exit_code": proc.returncode,
            "stdout": "",
            "stderr": stderr,
            "elapsed_seconds": round(elapsed, 2),
            "truncated": truncated,
            "stdout_file": str(stdout_file),
        }
    stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    return {
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "elapsed_seconds": round(elapsed, 2),
        "truncated": truncated,
    }


def _resolve_binary(binary: str) -> str:
    resolved = shutil.which(binary)
    if not resolved:
        raise ToolExecutionError(f"Binary not on PATH: {binary!r}")
    return resolved


def _assert_runnable(tool: ToolRecord) -> None:
    if tool.verification.status == "bad":
        raise ToolExecutionError(
            f"{tool.tool_id} ({tool.binary}) is marked do not use. "
            f"{tool.verification.detail or 'verification failed'}"
        )
    if tool.verification.status == "unavailable":
        raise ToolExecutionError(
            f"{tool.tool_id} ({tool.binary}) is not installed on this host"
        )
    if not tool.verification.agent_runnable:
        raise ToolExecutionError(
            f"{tool.tool_id} ({tool.binary}) is not runnable on this host"
        )
    if not shutil.which(tool.binary):
        raise ToolExecutionError(f"Binary not on PATH: {tool.binary!r}")


def _sleuthkit_offset_inode(extra_args: list[str]) -> tuple[str | None, str | None]:
    offset: str | None = None
    inode: str | None = None
    i = 0
    while i < len(extra_args):
        arg = extra_args[i]
        if arg == "-o" and i + 1 < len(extra_args):
            offset = extra_args[i + 1]
            i += 2
            continue
        if not arg.startswith("-"):
            inode = arg
        i += 1
    return offset, inode


def _istat_size_bytes(image_path: Path, offset: str, inode: str) -> int | None:
    istat = shutil.which("istat")
    if not istat:
        return None
    cmd = [istat, "-o", offset, str(image_path), inode]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ICAT_ISTAT_TIMEOUT,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    match = re.search(r"(?:Size|size):\s*(\d+)", proc.stdout)
    if match:
        return int(match.group(1))
    return None


def _inode_stream_preflight(
    *,
    image_path: Path,
    extra_args: list[str],
    scratch: Path,
) -> tuple[Path | None, int | None]:
    offset, inode = _sleuthkit_offset_inode(extra_args)
    if not offset or not inode:
        return None, None
    size = _istat_size_bytes(image_path, offset, inode)
    return scratch / f"icat_{inode.replace('-', '_')}.bin", size


def _execute_icat_capped(
    cmd: list[str],
    *,
    timeout: int,
    cwd: Path,
    out_file: Path,
    max_bytes: int,
    case_id: str,
) -> dict[str, Any]:
    start = time.monotonic()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd),
        shell=False,
    )
    written = 0
    truncated = False
    stderr_chunks: list[bytes] = []
    with out_file.open("wb") as handle:
        assert proc.stdout is not None
        while True:
            if written >= max_bytes:
                truncated = True
                proc.kill()
                break
            chunk = proc.stdout.read(min(65536, max_bytes - written))
            if not chunk:
                break
            handle.write(chunk)
            written += len(chunk)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise ToolExecutionError(f"Timed out after {timeout}s")
    if proc.stderr:
        stderr_chunks.append(proc.stderr.read(MAX_OUTPUT_BYTES // 4))
    elapsed = time.monotonic() - start
    if proc.returncode not in (0, None) and not truncated and proc.returncode != -9:
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        hint = stderr[:500] or out_file.read_bytes()[:200].decode("utf-8", errors="replace")
        raise ToolExecutionError(f"icat failed (exit {proc.returncode}): {hint}")
    preview_bytes = out_file.read_bytes()[:2000]
    preview = preview_bytes.decode("utf-8", errors="replace")
    if truncated:
        preview = (
            f"[extract capped at {max_bytes} bytes — full file at scratch path]\n{preview}"
        )
    output_meta = describe_output_file(out_file, case_id=case_id)
    return {
        "exit_code": 0 if truncated or proc.returncode == 0 else proc.returncode,
        "stdout": preview,
        "stderr": b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        "elapsed_seconds": round(elapsed, 2),
        "truncated": truncated or bool(output_meta.get("output_bytes", 0) > max_bytes),
        "extracted_file": str(out_file),
        "extracted_bytes": written,
        **output_meta,
    }


def _normalize_sleuthkit_extra_args(extra_args: list[str]) -> list[str]:
    return [arg for arg in extra_args if arg != INODE_PLACEHOLDER]


def _sleuthkit_failure_hint(tool: ToolRecord, extra_args: list[str]) -> str | None:
    if tool.category != "sleuthkit" or tool.input.style != "positional":
        return None
    if tool.name == "fls":
        return (
            "fls failed — list a directory inode after the image. "
            'Use extra_args like ["-o", "63", "-l", "23117"].'
        )
    if tool.name == "icat":
        return (
            "icat failed — extract file bytes by inode after the image. "
            'Use extra_args like ["-o", "63", "12204-128-6"]. '
            "Then analyze_scratch on the scratch file."
        )
    return None


def _split_sleuthkit_args(extra_args: list[str]) -> tuple[list[str], list[str]]:
    flags: list[str] = []
    trailing: list[str] = []
    flags_without_value = frozenset(
        {"-l", "-d", "-D", "-p", "-r", "-F", "-m", "-u", "-f", "-s"}
    )
    i = 0
    while i < len(extra_args):
        arg = extra_args[i]
        if arg == INODE_PLACEHOLDER:
            i += 1
            continue
        if arg.startswith("-"):
            flags.append(arg)
            if arg in flags_without_value:
                i += 1
                continue
            if i + 1 < len(extra_args) and not extra_args[i + 1].startswith("-"):
                flags.append(extra_args[i + 1])
                i += 2
                continue
            i += 1
        else:
            trailing.append(arg)
            i += 1
    return flags, trailing


def _build_command(
    tool: ToolRecord,
    input_path: Path,
    extra_args: list[str],
) -> list[str]:
    binary = _resolve_binary(tool.binary)
    if is_denied(Path(binary).name):
        raise ToolExecutionError(f"Binary blocked by policy: {tool.binary}")
    args = sanitize_extra_args(extra_args, tool_name=tool.name)
    if tool.category == "sleuthkit" and tool.input.style == "positional":
        args = _normalize_sleuthkit_extra_args(args)
    cmd = [binary]
    if tool.input.style == "flag" and tool.input.flag:
        cmd.extend([tool.input.flag, str(input_path)])
        cmd.extend(args)
    elif tool.input.style == "positional" and tool.category == "sleuthkit":
        flags, trailing = _split_sleuthkit_args(args)
        cmd.extend(flags)
        cmd.append(str(input_path))
        cmd.extend(trailing)
    elif tool.input.style == "positional":
        cmd.append(str(input_path))
        cmd.extend(args)
    else:
        cmd.extend(args)
    return cmd


def _finalize_output_dir(
    out_root: Path,
    tool: ToolRecord,
    audit_id: str,
    *,
    stderr: str,
) -> list[str]:
    out_root.mkdir(parents=True, exist_ok=True)
    saved: list[str] = []
    stdout_path = out_root / "stdout.txt"
    if stdout_path.is_file():
        saved.append(str(stdout_path))
    if stderr:
        stderr_path = out_root / "stderr.txt"
        stderr_path.write_text(stderr, encoding="utf-8")
        saved.append(str(stderr_path))
    meta = out_root / "run.meta.txt"
    meta.write_text(
        "\n".join(
            [
                f"tool_id={tool.tool_id}",
                f"tool_name={tool.name}",
                f"audit_id={audit_id}",
                f"ts={datetime.now(timezone.utc).isoformat()}",
            ]
        ),
        encoding="utf-8",
    )
    saved.append(str(meta))
    return saved


def _log_run(
    *,
    case_id: str,
    audit_id: str,
    tool: ToolRecord,
    purpose: str,
    why: str,
    cmd: list[str],
    input_relpath: str,
    input_sha256: str,
    exit_code: int,
    elapsed_ms: float,
    output_files: list[str],
    stdout_preview: str,
    error: str = "",
) -> None:
    scratch_refs = [
        scratch_relpath(case_id, path)
        for path in output_files
        if Path(path).is_file()
    ]
    append_audit(
        case_id=case_id,
        audit_id=audit_id,
        tool_id=tool.tool_id,
        tool_name=tool.name,
        purpose=purpose,
        why=why,
        command=cmd,
        input_relpath=input_relpath,
        input_sha256=input_sha256,
        exit_code=exit_code,
        elapsed_ms=elapsed_ms,
        output_files=output_files,
        stdout_preview=stdout_preview,
        error=error,
    )
    append_tool_log(
        case_id=case_id,
        audit_id=audit_id,
        tool_id=tool.tool_id,
        tool_name=tool.name,
        purpose=purpose,
        command=cmd,
        input_relpath=input_relpath,
        exit_code=exit_code,
        scratch_refs=scratch_refs,
        stdout_preview=stdout_preview,
        error=error,
    )


def run_sift_tool(
    *,
    tool_id: str,
    case_id: str,
    input_relpath: str,
    purpose: str,
    why: str,
    extra_args: list[str] | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Execute one catalog tool against R2 sandbox evidence; write output to scratch."""
    try:
        tool = get_tool(tool_id)
    except ToolCatalogError as exc:
        raise ToolExecutionError(str(exc)) from exc
    _assert_runnable(tool)

    extra = list(extra_args or [])
    scratch = scratch_dir(case_id)
    validate_output_args(extra, scratch, tool.name)

    input_path = resolve_sandbox_input(case_id, input_relpath)
    input_sha256 = sha256_file(input_path)

    audit_id = next_audit_id()
    out_root = scratch / f"{audit_id}_{tool.tool_id}_{tool.name}"
    if tool.output.style == "scratch_dir_trailing":
        output_dir = out_root / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        extra = list(extra) + [str(output_dir)]
    cmd = _build_command(tool, input_path, extra)
    stdout_file = out_root / "stdout.txt"
    start = time.monotonic()
    stream_out: Path | None = None
    stream_source_bytes: int | None = None
    if tool.output.style == "inode_stream":
        stream_out, stream_source_bytes = _inode_stream_preflight(
            image_path=input_path,
            extra_args=extra,
            scratch=scratch / audit_id,
        )

    try:
        if tool.output.style == "inode_stream" and stream_out is not None:
            cap = ICAT_MAX_BYTES
            if stream_source_bytes is not None:
                cap = min(ICAT_MAX_BYTES, stream_source_bytes)
            result = _execute_icat_capped(
                cmd,
                timeout=min(timeout or tool.timeout_seconds or DEFAULT_TIMEOUT, 180),
                cwd=scratch,
                out_file=stream_out,
                max_bytes=max(cap, 1),
                case_id=case_id,
            )
            if stream_source_bytes and stream_source_bytes > cap:
                result["source_bytes"] = stream_source_bytes
                result["truncated"] = True
        else:
            result = _execute(
                cmd,
                timeout=timeout or tool.timeout_seconds or DEFAULT_TIMEOUT,
                cwd=scratch,
                stdout_file=stdout_file,
            )
    except ToolExecutionError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        _log_run(
            case_id=case_id,
            audit_id=audit_id,
            tool=tool,
            purpose=purpose,
            why=why,
            cmd=cmd,
            input_relpath=input_relpath,
            input_sha256=input_sha256,
            exit_code=-1,
            elapsed_ms=elapsed_ms,
            output_files=[],
            stdout_preview="",
            error=str(exc),
        )
        raise

    elapsed_ms = (time.monotonic() - start) * 1000
    primary_file = Path(result["extracted_file"]) if result.get("extracted_file") else stdout_file
    if tool.output.style == "inode_stream" and stream_out is not None:
        primary_file = stream_out
    output_files = _finalize_output_dir(
        out_root if primary_file == stdout_file else primary_file.parent,
        tool,
        audit_id,
        stderr=result.get("stderr") or "",
    )
    if result.get("extracted_file") and str(result["extracted_file"]) not in output_files:
        output_files.insert(0, result["extracted_file"])

    output_meta = describe_output_file(
        primary_file,
        case_id=case_id,
        truncated=bool(result.get("truncated")),
        source_bytes=result.get("source_bytes"),
    )
    audit_preview = str(
        output_meta.get("stdout_preview") or read_text_preview(primary_file)
    )[:2000]

    _log_run(
        case_id=case_id,
        audit_id=audit_id,
        tool=tool,
        purpose=purpose,
        why=why,
        cmd=cmd,
        input_relpath=input_relpath,
        input_sha256=input_sha256,
        exit_code=result["exit_code"],
        elapsed_ms=elapsed_ms,
        output_files=output_files,
        stdout_preview=audit_preview,
    )

    payload: dict[str, Any] = {
        "ok": result["exit_code"] == 0,
        "audit_id": audit_id,
        "tool_id": tool.tool_id,
        "tool_name": tool.name,
        "case_id": case_id,
        "exit_code": result["exit_code"],
        "elapsed_seconds": result["elapsed_seconds"],
        "stdout_preview": audit_preview,
        "preview": output_meta.get("preview"),
        "stderr_preview": (result.get("stderr") or "")[:1000],
        "truncated": result.get("truncated", False),
        "extracted_file": result.get("extracted_file"),
        "extracted_bytes": result.get("extracted_bytes"),
        **output_meta,
    }
    if result["exit_code"] != 0:
        hint = _sleuthkit_failure_hint(tool, extra)
        if hint:
            payload["harness_hint"] = hint
    return payload
