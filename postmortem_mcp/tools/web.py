"""Web server log and upload artifact MCP tools."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.paths import resolve_web_artifact_path, resolve_web_log_path
from postmortem_mcp.web_parse import inspect_web_artifact, parse_access_log


def web_parse_access_log(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse web access logs (Apache/nginx) for attack patterns and scanner traffic."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_web_log_path(artifact_relpath)
        args["artifact_path"] = str(path)
        payload = parse_access_log(path, max_records=max_records)
        return payload

    return run_audited_tool(
        case_id=case_id,
        tool="web_parse_access_log",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def web_inspect_artifact(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_snippets: int = 20,
) -> dict:
    """Inspect PHP/HTML upload artifacts for webshell code indicators."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_snippets": max_snippets,
    }

    def execute() -> dict[str, Any]:
        path = resolve_web_artifact_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return inspect_web_artifact(path, max_snippets=max_snippets)

    return run_audited_tool(
        case_id=case_id,
        tool="web_inspect_artifact",
        args=args,
        iteration=iteration,
        execute=execute,
    )
