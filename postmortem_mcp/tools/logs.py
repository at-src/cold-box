"""Structured log MCP tools (JSONL / NDJSON)."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.log_parse import parse_structured_log
from postmortem_mcp.paths import resolve_structured_log_path


def logs_parse_structured(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse JSONL/NDJSON application or journal logs for security-relevant events."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_structured_log_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_structured_log(path, max_records=max_records)

    return run_audited_tool(
        case_id=case_id,
        tool="logs_parse_structured",
        args=args,
        iteration=iteration,
        execute=execute,
    )
