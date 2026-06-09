"""Memory analysis MCP tools."""

from __future__ import annotations

from postmortem_evidence.guard import EvidencePathError, resolve_read_path
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.config import vol3_binary
from postmortem_mcp.vol import run_pslist


def mem_pslist(
    case_id: str,
    memory_relpath: str,
    *,
    iteration: int = 0,
) -> dict:
    """List processes from a Windows memory image (Volatility pslist)."""
    args = {
        "case_id": case_id,
        "memory_relpath": memory_relpath,
    }

    def execute() -> dict:
        memory_path = resolve_read_path(memory_relpath)
        if not memory_path.is_file():
            raise EvidencePathError(f"Memory image must be a file: {memory_path}")
        args["memory_path"] = str(memory_path)
        return run_pslist(memory_path, vol_binary=vol3_binary())

    return run_audited_tool(
        case_id=case_id,
        tool="mem_pslist",
        args=args,
        iteration=iteration,
        execute=execute,
    )
