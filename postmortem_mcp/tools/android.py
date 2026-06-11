"""Android mobile forensic MCP tools."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.android_parse import probe_android_case, scan_android_artifacts
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.paths import resolve_case_directory


def android_probe(case_id: str, case_relpath: str, *, iteration: int = 0) -> dict:
    """Inventory Android mtd/sdcard images and parse acquisition notes."""
    args = {"case_id": case_id, "case_relpath": case_relpath}

    def execute() -> dict[str, Any]:
        case_root = resolve_case_directory(case_relpath)
        args["case_path"] = str(case_root)
        return probe_android_case(case_root)

    return run_audited_tool(
        case_id=case_id,
        tool="android_probe",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def android_scan_artifacts(
    case_id: str,
    search_root_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 80,
) -> dict:
    """Scan Android evidence for acquisition integrity signals and mobile artifacts."""
    args = {
        "case_id": case_id,
        "search_root_relpath": search_root_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        case_root = resolve_case_directory(search_root_relpath)
        args["case_path"] = str(case_root)
        payload = scan_android_artifacts(case_root, max_records=max_records)
        if payload["finding_count"] > max_records:
            payload["truncated"] = True
            payload["record_count"] = max_records
        return payload

    return run_audited_tool(
        case_id=case_id,
        tool="android_scan_artifacts",
        args=args,
        iteration=iteration,
        execute=execute,
    )
