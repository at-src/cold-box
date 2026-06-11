"""macOS forensic MCP tools."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.macos_parse import probe_macos_ad1, scan_macos_ad1
from postmortem_mcp.paths import resolve_readonly_file


def macos_probe(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
) -> dict:
    """Probe macOS AD1 custom-content image and companion manifest."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath}

    def execute() -> dict[str, Any]:
        path = resolve_readonly_file(artifact_relpath)
        args["artifact_path"] = str(path)
        return probe_macos_ad1(path)

    return run_audited_tool(
        case_id=case_id,
        tool="macos_probe",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def macos_scan_artifacts(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 80,
) -> dict:
    """Strings/manifest sweep of macOS AD1 for users, Spotlight, Safari, Slack."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_readonly_file(artifact_relpath)
        args["artifact_path"] = str(path)
        return scan_macos_ad1(path, max_records=max_records)

    return run_audited_tool(
        case_id=case_id,
        tool="macos_scan_artifacts",
        args=args,
        iteration=iteration,
        execute=execute,
    )
