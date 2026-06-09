"""Volatility 3 subprocess helpers."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any


def parse_vol_process_table(output: str) -> list[dict[str, Any]]:
    """Parse windows.pslist / windows.psscan tabular output."""
    lines = output.splitlines()
    header_idx = None
    headers: list[str] = []

    for idx, line in enumerate(lines):
        if line.startswith("PID\t") and "PPID" in line and "ImageFileName" in line:
            header_idx = idx
            headers = line.split("\t")
            break

    if header_idx is None:
        raise RuntimeError("vol process output missing PID header row")

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


def parse_cmdline_table(output: str) -> list[dict[str, Any]]:
    """Parse windows.cmdline tabular output."""
    lines = output.splitlines()
    header_idx = None
    for idx, line in enumerate(lines):
        if line.startswith("PID\t") and "Process" in line and "Args" in line:
            header_idx = idx
            break

    if header_idx is None:
        raise RuntimeError("vol cmdline output missing PID header row")

    rows: list[dict[str, Any]] = []
    for line in lines[header_idx + 1 :]:
        if not line.strip() or line.startswith("Progress:") or line.startswith("Volatility"):
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        pid, process, args = parts
        rows.append({"pid": int(pid), "process": process, "args": args})
    return rows


def run_vol_plugin(
    memory_path: Path,
    plugin: str,
    *,
    vol_binary: str,
    parser: Callable[[str], list[dict[str, Any]]],
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """Run a Volatility plugin and return structured JSON."""
    proc = subprocess.run(
        [vol_binary, "-f", str(memory_path), plugin],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "volatility failed"
        raise RuntimeError(detail)

    rows = parser(proc.stdout)
    return {
        "source": str(memory_path),
        "plugin": plugin,
        "row_count": len(rows),
        "rows": rows,
    }


def run_pslist(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.pslist",
        vol_binary=vol_binary,
        parser=parse_vol_process_table,
        timeout_sec=timeout_sec,
    )
    data["process_count"] = data["row_count"]
    data["processes"] = data.pop("rows")
    return data


def run_psscan(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.psscan",
        vol_binary=vol_binary,
        parser=parse_vol_process_table,
        timeout_sec=timeout_sec,
    )
    data["process_count"] = data["row_count"]
    data["processes"] = data.pop("rows")
    return data


def run_cmdline(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.cmdline",
        vol_binary=vol_binary,
        parser=parse_cmdline_table,
        timeout_sec=timeout_sec,
    )
    data["cmdline_count"] = data["row_count"]
    data["cmdlines"] = data.pop("rows")
    return data


# Backward-compatible alias used in tests
parse_pslist_table = parse_vol_process_table
