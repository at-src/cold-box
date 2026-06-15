"""Agent-facing warnings for high-cost SIFT tools."""

from __future__ import annotations

from typing import Any

# execution_profile: trivial | moderate | heavy
_TOOL_GUIDANCE: dict[str, dict[str, str]] = {
    "blkls": {
        "execution_profile": "heavy",
        "agent_guidance": (
            "Dumps raw unallocated block DATA to stdout (often megabytes–gigabytes). "
            "Slow, hits the 50MB scratch cap quickly, and can stall the case. "
            "Prefer fls/ils/icat/strings for deleted-file questions. "
            "Use blkls only when you must carve unallocated slack and no lighter tool suffices."
        ),
    },
    "blkcat": {
        "execution_profile": "heavy",
        "agent_guidance": (
            "Reads one disk block at a time but still streams binary data. "
            "Prefer icat on a known inode. Use blkcat only for a specific block address "
            "after fls/ils identified it."
        ),
    },
    "ewfexport": {
        "execution_profile": "heavy",
        "agent_guidance": (
            "Exports the full E01 to raw — multi-GB output and long runtime. "
            "Prefer ewfverify, ewfinfo, mmls, fls, icat on the E01 directly. "
            "Use ewfexport only when a downstream tool requires a raw DD and nothing else works."
        ),
    },
    "tsk_recover": {
        "execution_profile": "heavy",
        "agent_guidance": (
            "Bulk file recovery — can write thousands of files and run for a long time. "
            "Prefer targeted icat on inodes you already identified via fls. "
            "Use tsk_recover only for broad carve-all-deleted when inode list is impractical."
        ),
    },
    "bulk_extractor": {
        "execution_profile": "heavy",
        "agent_guidance": (
            "Scans the entire image and writes a large feature directory tree. "
            "Prefer grep/strings/icat on known artifacts first. "
            "Use bulk_extractor for broad unknown-content triage, not a single named file."
        ),
    },
    "mmls": {
        "execution_profile": "moderate",
        "agent_guidance": (
            "Fast partition listing — usually fine. Required once per image before -o offset tools."
        ),
    },
}


def enrich_tool_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Attach execution_profile / agent_guidance when known."""
    name = str(row.get("name") or "").lower()
    meta = _TOOL_GUIDANCE.get(name)
    if not meta:
        return row
    out = dict(row)
    out["execution_profile"] = meta["execution_profile"]
    out["agent_guidance"] = meta["agent_guidance"]
    return out


def enrich_describe_dict(row: dict[str, Any]) -> dict[str, Any]:
    out = enrich_tool_dict(row)
    guidance = out.get("agent_guidance")
    if guidance and guidance not in str(out.get("description", "")):
        profile = out.get("execution_profile", "moderate")
        out["description"] = (
            f"{out['description']} [{profile.upper()}] {guidance}"
        )
    return out
