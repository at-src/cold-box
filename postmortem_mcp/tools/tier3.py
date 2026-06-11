"""Tier-3 breadth tools — exfil channel scan and YARA/pattern malware scan."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.exfil_parse import scan_exfil_channels
from postmortem_mcp.paths import resolve_case_directory
from postmortem_mcp.yara_scan import scan_with_yara


def disk_scan_exfil(
    case_id: str,
    search_root_relpath: str,
    *,
    iteration: int = 0,
    max_hits: int = 40,
) -> dict:
    """Scan evidence for email / cloud / optical exfiltration indicators (NIST NDLC themes)."""
    args: dict[str, Any] = {
        "case_id": case_id,
        "search_root_relpath": search_root_relpath,
        "max_hits": max_hits,
    }

    def execute() -> dict[str, Any]:
        root = resolve_case_directory(search_root_relpath)
        args["search_root"] = str(root)
        return scan_exfil_channels(root, max_hits=max_hits)

    return run_audited_tool(
        case_id=case_id,
        tool="disk_scan_exfil",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def yara_scan_evidence(
    case_id: str,
    search_root_relpath: str,
    *,
    iteration: int = 0,
    max_matches: int = 30,
) -> dict:
    """YARA scan (or regex fallback) for suspicious strings / malware themes (F-CFR-009)."""
    args: dict[str, Any] = {
        "case_id": case_id,
        "search_root_relpath": search_root_relpath,
        "max_matches": max_matches,
    }

    def execute() -> dict[str, Any]:
        root = resolve_case_directory(search_root_relpath)
        args["search_root"] = str(root)
        return scan_with_yara(root, max_matches=max_matches)

    return run_audited_tool(
        case_id=case_id,
        tool="yara_scan_evidence",
        args=args,
        iteration=iteration,
        execute=execute,
    )
