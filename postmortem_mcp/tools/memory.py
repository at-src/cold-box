"""Memory analysis MCP tools."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.config import vol3_binary
from postmortem_mcp.paths import resolve_memory_path
from postmortem_mcp.vol import (
    run_cmdline,
    run_cmdscan,
    run_dlllist,
    run_filescan,
    run_handles,
    run_hivelist,
    run_malfind,
    run_modules,
    run_netscan,
    run_pslist,
    run_psscan,
    run_pstree,
    run_svcscan,
)


def _cap_rows(data: dict[str, Any], key: str, count_key: str, max_records: int) -> dict[str, Any]:
    rows = data[key]
    total = len(rows)
    if total > max_records:
        data["truncated"] = True
        data["record_count"] = total
        data["returned_count"] = max_records
        data[key] = rows[:max_records]
        data[count_key] = max_records
    else:
        data["truncated"] = False
        data["record_count"] = total
        data["returned_count"] = total
    return data


def _memory_tool(
    *,
    case_id: str,
    memory_relpath: str,
    tool: str,
    iteration: int,
    max_records: int,
    runner,
) -> dict:
    args: dict[str, Any] = {
        "case_id": case_id,
        "memory_relpath": memory_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        memory_path = resolve_memory_path(memory_relpath)
        args["memory_path"] = str(memory_path)
        data = runner(memory_path, vol_binary=vol3_binary())
        if tool == "mem_pslist":
            return _cap_rows(data, "processes", "process_count", max_records)
        if tool == "mem_psscan":
            return _cap_rows(data, "processes", "process_count", max_records)
        if tool == "mem_netscan":
            return _cap_rows(data, "connections", "connection_count", max_records)
        if tool == "mem_malfind":
            return _cap_rows(data, "findings", "finding_count", max_records)
        if tool == "mem_pstree":
            return _cap_rows(data, "nodes", "node_count", max_records)
        if tool == "mem_dlllist":
            return _cap_rows(data, "dlls", "dll_count", max_records)
        if tool == "mem_svcscan":
            return _cap_rows(data, "services", "service_count", max_records)
        if tool == "mem_hivelist":
            return _cap_rows(data, "hives", "hive_count", max_records)
        if tool == "mem_filescan":
            return _cap_rows(data, "files", "file_count", max_records)
        if tool == "mem_cmdscan":
            return _cap_rows(data, "commands", "command_count", max_records)
        if tool == "mem_handles":
            return _cap_rows(data, "handles", "handle_count", max_records)
        if tool == "mem_modules":
            return _cap_rows(data, "modules", "module_count", max_records)
        return _cap_rows(data, "cmdlines", "cmdline_count", max_records)

    return run_audited_tool(
        case_id=case_id,
        tool=tool,
        args=args,
        iteration=iteration,
        execute=execute,
    )


def mem_pslist(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """List Windows processes from a memory image (Volatility pslist)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_pslist",
        iteration=iteration,
        max_records=max_records,
        runner=run_pslist,
    )


def mem_psscan(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Scan for hidden/unlinked processes in a memory image (Volatility psscan)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_psscan",
        iteration=iteration,
        max_records=max_records,
        runner=run_psscan,
    )


def mem_cmdline(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Extract process command lines from a memory image (Volatility cmdline)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_cmdline",
        iteration=iteration,
        max_records=max_records,
        runner=run_cmdline,
    )


def mem_netscan(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """List network connections and sockets from a memory image (Volatility netscan)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_netscan",
        iteration=iteration,
        max_records=max_records,
        runner=run_netscan,
    )


def mem_malfind(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Find injected / RWX memory regions (Volatility malfind)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_malfind",
        iteration=iteration,
        max_records=max_records,
        runner=run_malfind,
    )


def mem_pstree(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Build parent/child process tree from memory (Volatility pstree)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_pstree",
        iteration=iteration,
        max_records=max_records,
        runner=run_pstree,
    )


def mem_dlllist(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 1000,
) -> dict:
    """List loaded DLLs per process — injection and hollowing follow-up (Volatility dlllist)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_dlllist",
        iteration=iteration,
        max_records=max_records,
        runner=run_dlllist,
    )


def mem_svcscan(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Enumerate Windows services from memory — persistence triage (Volatility svcscan)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_svcscan",
        iteration=iteration,
        max_records=max_records,
        runner=run_svcscan,
    )


def mem_hivelist(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """List registry hives loaded in memory (Volatility hivelist)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_hivelist",
        iteration=iteration,
        max_records=max_records,
        runner=run_hivelist,
    )


def mem_filescan(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Scan memory for file object artifacts (Volatility filescan)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_filescan",
        iteration=iteration,
        max_records=max_records,
        runner=run_filescan,
    )


def mem_cmdscan(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 300,
) -> dict:
    """Recover command history buffers from memory (Volatility cmdscan)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_cmdscan",
        iteration=iteration,
        max_records=max_records,
        runner=run_cmdscan,
    )


def mem_handles(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """List open handles per process from memory (Volatility handles)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_handles",
        iteration=iteration,
        max_records=max_records,
        runner=run_handles,
    )


def mem_modules(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """List kernel modules loaded in memory (Volatility modules)."""
    return _memory_tool(
        case_id=case_id,
        memory_relpath=memory_relpath,
        tool="mem_modules",
        iteration=iteration,
        max_records=max_records,
        runner=run_modules,
    )
