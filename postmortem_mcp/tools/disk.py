"""Disk artifact MCP tools."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.config import (
    amcache_parser_binary,
    evtx_ecmd_binary,
    mftecmd_binary,
    prefetch_parser,
    scratch_dir,
)
from postmortem_mcp.ez_tools import parse_amcache, parse_evtx, parse_mft
from postmortem_mcp.paths import (
    resolve_amcache_path,
    resolve_evtx_path,
    resolve_mft_path,
    resolve_prefetch_path,
)


def _parse_prefetch_file(path) -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, prefetch_parser(), str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "prefetch parse failed")
    return json.loads(proc.stdout)


def disk_parse_prefetch(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
) -> dict:
    """Parse a Windows prefetch (.pf) file into structured JSON."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath}

    def execute() -> dict[str, Any]:
        path = resolve_prefetch_path(artifact_relpath)
        args["artifact_path"] = str(path)
        payload = _parse_prefetch_file(path)
        return {"source": str(path), "parser": "sccainfo", "prefetch": payload}

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_prefetch",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_amcache(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse Amcache.hve into structured program execution records."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_amcache_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_amcache(
            path,
            binary=amcache_parser_binary(),
            scratch_dir=scratch_dir(case_id),
            max_records=max_records,
        )

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_amcache",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_evtx(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Parse a Windows EVTX event log into structured records."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_evtx_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_evtx(
            path,
            binary=evtx_ecmd_binary(),
            scratch_dir=scratch_dir(case_id),
            max_records=max_records,
        )

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_evtx",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_mft(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse an extracted $MFT into structured file records."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_mft_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_mft(
            path,
            binary=mftecmd_binary(),
            scratch_dir=scratch_dir(case_id),
            max_records=max_records,
        )

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_mft",
        args=args,
        iteration=iteration,
        execute=execute,
    )
