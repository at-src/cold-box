"""Scratch output paths and agent-facing file metadata."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from cold_box_room.r1.paths import case_records_dir

PREVIEW_CHARS = int(os.environ.get("COLD_BOX_AGENT_PREVIEW_CHARS", "1200"))
PREVIEW_LINES = int(os.environ.get("COLD_BOX_AGENT_PREVIEW_LINES", "15"))
MAX_SCRATCH_FILE_BYTES = int(
    os.environ.get("COLD_BOX_MAX_SCRATCH_FILE_BYTES", str(50 * 1024 * 1024))
)


def scratch_dir(case_id: str) -> Path:
    path = case_records_dir(case_id) / "scratch"
    path.mkdir(parents=True, exist_ok=True)
    return path


def scratch_root(case_id: str) -> Path:
    return scratch_dir(case_id)


def scratch_relpath(case_id: str, path: str | Path) -> str:
    root = scratch_root(case_id).resolve()
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(root))
    except ValueError:
        return resolved.name


def count_lines(path: Path) -> int:
    if not path.is_file() or path.stat().st_size == 0:
        return 0
    try:
        proc = subprocess.run(
            ["wc", "-l", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return int(proc.stdout.split()[0])
    except (subprocess.TimeoutExpired, ValueError, IndexError):
        pass
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def read_text_preview(path: Path) -> str:
    if not path.is_file():
        return ""
    with path.open("rb") as handle:
        raw = handle.read(PREVIEW_CHARS + 512)
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > PREVIEW_LINES:
        text = "\n".join(lines[:PREVIEW_LINES])
    if len(text) > PREVIEW_CHARS:
        text = text[:PREVIEW_CHARS]
    return text


def stream_pipe_to_file(
    pipe,
    out_path: Path,
    *,
    max_bytes: int = MAX_SCRATCH_FILE_BYTES,
) -> tuple[int, bool]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    truncated = False
    with out_path.open("wb") as handle:
        while True:
            chunk = pipe.read(min(65536, max(0, max_bytes - written)))
            if not chunk:
                break
            handle.write(chunk)
            written += len(chunk)
            if written >= max_bytes:
                truncated = True
                break
    return written, truncated


def detect_content_kind(path: Path) -> str:
    if not path.is_file():
        return "missing"
    with path.open("rb") as handle:
        magic = handle.read(16)
    if magic.startswith(b"SQLite format 3"):
        return "sqlite"
    if magic.startswith((b"{", b"[")):
        return "json"
    if magic.startswith(b"<?xml") or magic.lstrip().startswith(b"<"):
        return "xml"
    if b"\x00" in magic:
        return "binary"
    return "text"


def describe_output_file(
    path: Path,
    *,
    case_id: str,
    truncated: bool = False,
    source_bytes: int | None = None,
) -> dict[str, object]:
    if not path.is_file():
        return {}

    size = path.stat().st_size
    rel = scratch_relpath(case_id, path)
    kind = detect_content_kind(path)
    lines = count_lines(path) if kind in {"text", "json", "xml", "sqlite"} else 0
    preview = read_text_preview(path) if kind in {"text", "json", "xml", "sqlite", "log"} else ""

    payload: dict[str, object] = {
        "scratch_file": rel,
        "output_bytes": size,
        "content_kind": kind,
        "output_note": (
            f"Tool output saved to `{rel}` ({kind}, {size} bytes"
            + (f", {lines} lines" if lines else "")
            + "). Use analyze_scratch to inspect."
        ),
        "inspect_via": "analyze_scratch",
        "stdout_preview": preview[:2000],
        "preview": preview[:PREVIEW_CHARS] if preview else None,
    }
    if lines:
        payload["output_lines"] = lines
    if truncated:
        payload["file_truncated"] = True
        if source_bytes is not None:
            payload["source_bytes"] = source_bytes
    return payload
