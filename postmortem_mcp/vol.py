"""Volatility 3 subprocess helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


def parse_pslist_table(output: str) -> list[dict[str, Any]]:
    """Parse windows.pslist tabular output into structured rows."""
    lines = output.splitlines()
    header_idx = None
    headers: list[str] = []

    for idx, line in enumerate(lines):
        if line.startswith("PID\t") and "PPID" in line:
            header_idx = idx
            headers = line.split("\t")
            break

    if header_idx is None:
        raise RuntimeError("pslist output missing PID header row")

    processes: list[dict[str, Any]] = []
    for line in lines[header_idx + 1 :]:
        if not line.strip():
            continue
        if line.startswith("Progress:") or line.startswith("Volatility"):
            continue
        parts = line.split("\t")
        if len(parts) != len(headers):
            continue
        row = dict(zip(headers, parts, strict=True))
        processes.append(
            {
                "pid": int(row["PID"]),
                "ppid": int(row["PPID"]),
                "name": row["ImageFileName"],
                "offset": row["Offset(V)"],
                "threads": int(row["Threads"]),
                "handles": int(row["Handles"]),
                "session_id": row["SessionId"],
                "wow64": row["Wow64"].lower() == "true",
                "create_time": row["CreateTime"],
                "exit_time": row["ExitTime"],
                "file_output": row["File output"],
            }
        )
    return processes


def run_pslist(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """Run Volatility windows.pslist and return structured JSON."""
    proc = subprocess.run(
        [vol_binary, "-f", str(memory_path), "windows.pslist"],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "volatility failed"
        raise RuntimeError(detail)

    processes = parse_pslist_table(proc.stdout)
    return {
        "source": str(memory_path),
        "plugin": "windows.pslist",
        "process_count": len(processes),
        "processes": processes,
    }
