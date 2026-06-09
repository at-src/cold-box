"""Audit wrapper for MCP tool execution."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from postmortem_audit import AuditLog
from postmortem_mcp.config import audit_log_path
from postmortem_mcp.responses import tool_response


def run_audited_tool(
    *,
    case_id: str,
    tool: str,
    args: dict[str, Any],
    iteration: int,
    execute: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a tool, append audit.jsonl, return JSON with audit_id."""
    log = AuditLog(audit_log_path(case_id))
    try:
        data = execute()
        audit_id = log.append(tool=tool, args=args, result=data, iteration=iteration)
        return tool_response(ok=True, tool=tool, audit_id=audit_id, data=data)
    except Exception as exc:
        error_result = {"ok": False, "error": str(exc), "tool": tool}
        audit_id = log.append(tool=tool, args=args, result=error_result, iteration=iteration)
        return tool_response(ok=False, tool=tool, audit_id=audit_id, error=str(exc))
