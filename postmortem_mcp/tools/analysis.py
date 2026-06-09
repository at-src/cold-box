"""Deep analysis MCP tools — filtered logs, registry, correlation, IOC search."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.config import (
    evtx_ecmd_binary,
    mftecmd_binary,
    recmd_binary,
    scratch_dir,
    vol3_binary,
)
from postmortem_mcp.ez_tools import (
    parse_evtx,
    parse_evtx_filtered,
    parse_mft,
    parse_mft_csv,
    parse_registry_hive,
)
from postmortem_mcp.paths import (
    resolve_case_directory,
    resolve_evtx_path,
    resolve_mft_path,
    resolve_memory_path,
    resolve_registry_path,
)
from postmortem_mcp.timeline import build_correlated_timeline, search_evidence_tree
from postmortem_mcp.vol import run_pslist


def disk_evtx_filter(
    case_id: str,
    artifact_relpath: str,
    event_ids: list[int] | None = None,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse Security/EVTX with Event ID filter and structured auth summary."""
    ids = event_ids or [4624, 4625, 4648, 4672]
    args: dict[str, Any] = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "event_ids": ids,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_evtx_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_evtx_filtered(
            path,
            binary=evtx_ecmd_binary(),
            scratch_dir=scratch_dir(case_id),
            event_ids=ids,
            max_records=max_records,
        )

    return run_audited_tool(
        case_id=case_id,
        tool="disk_evtx_filter",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_registry(
    case_id: str,
    artifact_relpath: str,
    key_path: str | None = None,
    search_string: str | None = None,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse registry hive for Run keys or persistence string search (RECmd)."""
    args: dict[str, Any] = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "key_path": key_path,
        "search_string": search_string,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_registry_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_registry_hive(
            path,
            binary=recmd_binary(),
            scratch_dir=scratch_dir(case_id),
            key_path=key_path,
            search_string=search_string,
            max_records=max_records,
        )

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_registry",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_correlate_timeline(
    case_id: str,
    evtx_relpath: str | None = None,
    mft_relpath: str | None = None,
    memory_relpath: str | None = None,
    *,
    iteration: int = 0,
    max_events: int = 300,
    max_records: int = 500,
) -> dict:
    """Cross-source timeline: merge EVTX auth events, MFT file times, and memory process starts."""
    args: dict[str, Any] = {
        "case_id": case_id,
        "evtx_relpath": evtx_relpath,
        "mft_relpath": mft_relpath,
        "memory_relpath": memory_relpath,
        "max_events": max_events,
    }

    def execute() -> dict[str, Any]:
        evtx_records: list[dict[str, Any]] | None = None
        mft_records: list[dict[str, Any]] | None = None
        memory_processes: list[dict[str, Any]] | None = None

        if evtx_relpath:
            evtx_path = resolve_evtx_path(evtx_relpath)
            args["evtx_path"] = str(evtx_path)
            evtx_records = parse_evtx(
                evtx_path,
                binary=evtx_ecmd_binary(),
                scratch_dir=scratch_dir(case_id),
                max_records=max_records,
            ).get("records") or []

        if mft_relpath:
            mft_path = resolve_mft_path(mft_relpath)
            args["mft_path"] = str(mft_path)
            if mft_path.suffix.lower() == ".csv":
                mft_records = parse_mft_csv(mft_path, max_records=max_records).get("records") or []
            else:
                mft_records = parse_mft(
                    mft_path,
                    binary=mftecmd_binary(),
                    scratch_dir=scratch_dir(case_id),
                    max_records=max_records,
                ).get("records") or []

        if memory_relpath:
            mem_path = resolve_memory_path(memory_relpath)
            args["memory_path"] = str(mem_path)
            pslist = run_pslist(mem_path, vol_binary=vol3_binary())
            memory_processes = pslist.get("processes") or []

        timeline = build_correlated_timeline(
            evtx_records=evtx_records,
            mft_records=mft_records,
            memory_processes=memory_processes,
            max_events=max_events,
        )
        timeline["parser"] = "cross-source-timeline"
        return timeline

    return run_audited_tool(
        case_id=case_id,
        tool="disk_correlate_timeline",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_search_artifacts(
    case_id: str,
    search_root_relpath: str,
    patterns: list[str],
    *,
    iteration: int = 0,
    max_hits: int = 50,
    max_file_bytes: int = 2_000_000,
) -> dict:
    """Search evidence tree for IOC strings (web shells, suspicious paths, keywords)."""
    args: dict[str, Any] = {
        "case_id": case_id,
        "search_root_relpath": search_root_relpath,
        "patterns": patterns,
        "max_hits": max_hits,
    }

    def execute() -> dict[str, Any]:
        root = resolve_case_directory(search_root_relpath)
        args["search_root"] = str(root)
        payload = search_evidence_tree(
            root,
            patterns,
            max_hits=max_hits,
            max_file_bytes=max_file_bytes,
        )
        payload["parser"] = "evidence-ioc-search"
        return payload

    return run_audited_tool(
        case_id=case_id,
        tool="disk_search_artifacts",
        args=args,
        iteration=iteration,
        execute=execute,
    )
