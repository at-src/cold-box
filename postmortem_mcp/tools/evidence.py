"""Evidence MCP tools."""

from __future__ import annotations

from typing import Any

from postmortem_evidence.manifest import build_manifest, manifest_digest
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.paths import resolve_case_directory


def evidence_manifest(
    case_id: str,
    case_relpath: str,
    *,
    iteration: int = 0,
) -> dict:
    """Build a SHA-256 manifest for all files under an evidence case directory."""
    args = {"case_id": case_id, "case_relpath": case_relpath}

    def execute() -> dict[str, Any]:
        case_path = resolve_case_directory(case_relpath)
        args["case_path"] = str(case_path)
        manifest = build_manifest(case_path)
        return {
            "case_root": str(case_path),
            "manifest_digest": manifest_digest(manifest),
            "file_count": manifest["file_count"],
            "generated_at": manifest["generated_at"],
            "files": manifest["files"],
        }

    return run_audited_tool(
        case_id=case_id,
        tool="evidence_manifest",
        args=args,
        iteration=iteration,
        execute=execute,
    )
