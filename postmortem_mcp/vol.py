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


def parse_vol_tab_table(output: str, *, required_columns: set[str]) -> list[dict[str, Any]]:
    """Parse generic Volatility tabular output into row dicts."""
    lines = output.splitlines()
    header_idx = None
    headers: list[str] = []
    for idx, line in enumerate(lines):
        if not line.strip() or line.startswith("Progress:") or line.startswith("Volatility"):
            continue
        cols = line.split("\t")
        if required_columns.issubset(set(cols)):
            header_idx = idx
            headers = cols
            break

    if header_idx is None:
        raise RuntimeError(f"vol output missing columns {sorted(required_columns)}")

    rows: list[dict[str, Any]] = []
    for line in lines[header_idx + 1 :]:
        if not line.strip() or line.startswith("Progress:") or line.startswith("Volatility"):
            continue
        parts = line.split("\t")
        if len(parts) != len(headers):
            continue
        row = dict(zip(headers, parts, strict=False))
        if "PID" in row:
            try:
                row["pid"] = int(row["PID"])
            except ValueError:
                row["pid"] = row["PID"]
        rows.append(row)
    return rows


def parse_netscan_table(output: str) -> list[dict[str, Any]]:
    return parse_vol_tab_table(
        output,
        required_columns={"PID", "Foreign Address", "Local Address"},
    )


def parse_malfind_blocks(output: str) -> list[dict[str, Any]]:
    """Parse windows.malfind block output into structured rows."""
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                rows.append(current)
                current = {}
            continue
        if stripped.startswith("Process:"):
            if current:
                rows.append(current)
            current = {"process": stripped.split(":", 1)[1].strip()}
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key_norm = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if key_norm == "pid":
            try:
                current["pid"] = int(value)
            except ValueError:
                current["pid"] = value
        else:
            current[key_norm] = value
    if current:
        rows.append(current)
    return rows


def run_netscan(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.netscan",
        vol_binary=vol_binary,
        parser=parse_netscan_table,
        timeout_sec=timeout_sec,
    )
    data["connection_count"] = data["row_count"]
    data["connections"] = data.pop("rows")
    return data


def run_malfind(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.malfind",
        vol_binary=vol_binary,
        parser=parse_malfind_blocks,
        timeout_sec=timeout_sec,
    )
    data["finding_count"] = data["row_count"]
    data["findings"] = data.pop("rows")
    return data


def parse_pstree_table(output: str) -> list[dict[str, Any]]:
    """Parse windows.pstree output with optional tree depth markers."""
    lines = output.splitlines()
    header_idx = None
    headers: list[str] = []
    for idx, line in enumerate(lines):
        if line.startswith("PID\t") and "PPID" in line and "ImageFileName" in line:
            header_idx = idx
            headers = line.split("\t")
            break
    if header_idx is None:
        raise RuntimeError("vol pstree output missing PID header row")

    nodes: list[dict[str, Any]] = []
    for line in lines[header_idx + 1 :]:
        if not line.strip() or line.startswith("Progress:") or line.startswith("Volatility"):
            continue
        depth = len(line) - len(line.lstrip("*"))
        stripped = line.lstrip("* \t")
        parts = stripped.split("\t")
        if len(parts) != len(headers):
            continue
        row = dict(zip(headers, parts, strict=False))
        nodes.append(
            {
                "depth": depth,
                "pid": int(row["PID"]),
                "ppid": int(row["PPID"]),
                "name": row["ImageFileName"],
                "cmd": row.get("Cmd") or row.get("Cmdline") or "",
                "path": row.get("Path") or "",
                "create_time": row.get("CreateTime"),
            }
        )
    return nodes


def parse_dlllist_table(output: str) -> list[dict[str, Any]]:
    return parse_vol_tab_table(output, required_columns={"PID", "Process", "Name", "Path"})


def parse_svcscan_table(output: str) -> list[dict[str, Any]]:
    return parse_vol_tab_table(
        output,
        required_columns={"Offset", "PID", "Name", "State", "Binary"},
    )


def run_pstree(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.pstree",
        vol_binary=vol_binary,
        parser=parse_pstree_table,
        timeout_sec=timeout_sec,
    )
    data["node_count"] = data["row_count"]
    data["nodes"] = data.pop("rows")
    return data


def run_dlllist(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.dlllist",
        vol_binary=vol_binary,
        parser=parse_dlllist_table,
        timeout_sec=timeout_sec,
    )
    data["dll_count"] = data["row_count"]
    data["dlls"] = data.pop("rows")
    return data


def run_svcscan(
    memory_path: Path,
    *,
    vol_binary: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    data = run_vol_plugin(
        memory_path,
        "windows.svcscan",
        vol_binary=vol_binary,
        parser=parse_svcscan_table,
        timeout_sec=timeout_sec,
    )
    data["service_count"] = data["row_count"]
    data["services"] = data.pop("rows")
    return data


# Backward-compatible alias used in tests
parse_pslist_table = parse_vol_process_table
