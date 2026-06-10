"""Disk artifact MCP tools."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from postmortem_mcp.artifact_parse import (
    is_placeholder_file,
    load_amcache_with_fallbacks,
    load_csv_records,
    load_json_sidecar,
    parse_evtx_csv_sidecar,
    parse_lnk_metadata,
    parse_recycle_bin,
    parse_scheduled_task_file,
    parse_setupapi_dev_log,
)
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.config import (
    amcache_parser_binary,
    evtx_ecmd_binary,
    mftecmd_binary,
    prefetch_parser,
    scratch_dir,
)
from postmortem_mcp.ez_tools import parse_amcache, parse_evtx, parse_mft, parse_mft_csv
from postmortem_mcp.timestomp import detect_timestomp_rows
from postmortem_mcp.paths import (
    resolve_amcache_path,
    resolve_case_directory,
    resolve_csv_artifact_path,
    resolve_evtx_path,
    resolve_lnk_path,
    resolve_mft_path,
    resolve_prefetch_path,
    resolve_scheduled_task_path,
    resolve_setupapi_path,
    resolve_text_or_dir_path,
    resolve_readonly_file,
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
        sidecar = path.with_suffix(".json")
        if sidecar.is_file():
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            payload.setdefault("source", str(path))
            payload["parser"] = "sidecar-json"
            return payload
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
        try:
            case_root = resolve_case_directory(".")
        except Exception:
            case_root = path.parent
        if is_placeholder_file(path):
            return load_amcache_with_fallbacks(
                path, case_root=case_root, max_records=max_records
            )
        try:
            return parse_amcache(
                path,
                binary=amcache_parser_binary(),
                scratch_dir=scratch_dir(case_id),
                max_records=max_records,
            )
        except Exception:
            return load_amcache_with_fallbacks(
                path, case_root=case_root, max_records=max_records
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
        if is_placeholder_file(path):
            sidecar = parse_evtx_csv_sidecar(path, max_records=max_records)
            if sidecar:
                return sidecar
        try:
            return parse_evtx(
                path,
                binary=evtx_ecmd_binary(),
                scratch_dir=scratch_dir(case_id),
                max_records=max_records,
            )
        except Exception:
            sidecar = parse_evtx_csv_sidecar(path, max_records=max_records)
            if sidecar:
                return sidecar
            raise

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


def disk_detect_timestomp(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 5000,
    tolerance_seconds: int = 1,
    executables_only: bool = False,
) -> dict:
    """Detect MFT $SI vs $FN timestomp anomalies (T1070.006)."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
        "tolerance_seconds": tolerance_seconds,
        "executables_only": executables_only,
    }

    def execute() -> dict[str, Any]:
        path = resolve_mft_path(artifact_relpath)
        args["artifact_path"] = str(path)
        if path.suffix.lower() == ".csv":
            parsed = parse_mft_csv(path, max_records=max_records)
        else:
            parsed = parse_mft(
                path,
                binary=mftecmd_binary(),
                scratch_dir=scratch_dir(case_id),
                max_records=max_records,
            )
        rows = parsed.get("records") or []
        findings = detect_timestomp_rows(
            rows,
            tolerance_seconds=tolerance_seconds,
            executables_only=executables_only,
        )
        return {
            "source": str(path),
            "parser": "mftecmd+timestomp",
            "rows_scanned": len(rows),
            "findings": findings,
            "findings_count": len(findings),
            "tolerance_seconds": tolerance_seconds,
            "executables_only": executables_only,
        }

    return run_audited_tool(
        case_id=case_id,
        tool="disk_detect_timestomp",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def _artifact_csv_tool(
    case_id: str,
    tool: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
    parser_label: str,
    resolver=resolve_csv_artifact_path,
) -> dict:
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolver(artifact_relpath)
        args["artifact_path"] = str(path)
        payload = load_csv_records(path, max_records=max_records)
        payload["parser"] = parser_label
        return payload

    return run_audited_tool(
        case_id=case_id,
        tool=tool,
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_setupapi(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Parse setupapi.dev.log for USB device insertion history (IP-KVM triage)."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_setupapi_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_setupapi_dev_log(path, max_records=max_records)

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_setupapi",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_scheduled_tasks(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 50,
) -> dict:
    """Parse a Windows scheduled task XML file for persistence triage."""
    del max_records
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath}

    def execute() -> dict[str, Any]:
        path = resolve_scheduled_task_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_scheduled_task_file(path)

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_scheduled_tasks",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_shimcache(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse AppCompat ShimCache CSV export for execution history."""
    return _artifact_csv_tool(
        case_id,
        "disk_parse_shimcache",
        artifact_relpath,
        iteration=iteration,
        max_records=max_records,
        parser_label="shimcache-csv",
    )


def disk_parse_userassist(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse UserAssist CSV export (disk artifact variant)."""
    return _artifact_csv_tool(
        case_id,
        "disk_parse_userassist",
        artifact_relpath,
        iteration=iteration,
        max_records=max_records,
        parser_label="userassist-csv",
    )


def disk_parse_lnk(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Parse Windows .lnk shortcut metadata (sidecar JSON when present)."""
    del max_records
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath}

    def execute() -> dict[str, Any]:
        path = resolve_lnk_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_lnk_metadata(path)

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_lnk",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_jumplist(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 300,
) -> dict:
    """Parse Jump List CSV export or sidecar JSON."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_readonly_file(artifact_relpath)
        args["artifact_path"] = str(path)
        sidecar = load_json_sidecar(path, max_records=max_records)
        if sidecar:
            sidecar["parser"] = "jumplist-sidecar"
            return sidecar
        if path.suffix.lower() == ".csv":
            payload = load_csv_records(path, max_records=max_records)
            payload["parser"] = "jumplist-csv"
            return payload
        raise RuntimeError("Jump list artifact requires .csv or sidecar JSON")

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_jumplist",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_srum(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 300,
) -> dict:
    """Parse SRUM database sidecar export (CSV/JSON)."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_readonly_file(artifact_relpath)
        args["artifact_path"] = str(path)
        sidecar = load_json_sidecar(path, max_records=max_records)
        if sidecar:
            sidecar["parser"] = "srum-sidecar"
            return sidecar
        if path.suffix.lower() == ".csv":
            payload = load_csv_records(path, max_records=max_records)
            payload["parser"] = "srum-csv"
            return payload
        return {
            "source": str(path),
            "parser": "srum-stub",
            "records": [{"path": path.name, "note": "SRUDB.dat present; attach CSV export"}],
            "record_count": 1,
            "returned_count": 1,
            "truncated": False,
        }

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_srum",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_usnjrnl(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse USN journal CSV export for file rename/delete activity."""
    return _artifact_csv_tool(
        case_id,
        "disk_parse_usnjrnl",
        artifact_relpath,
        iteration=iteration,
        max_records=max_records,
        parser_label="usnjrnl-csv",
        resolver=resolve_readonly_file,
    )


def disk_recycle_bin(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """List deleted files in $Recycle.Bin export or sidecar JSON."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_text_or_dir_path(artifact_relpath)
        args["artifact_path"] = str(path)
        payload = parse_recycle_bin(path, max_records=max_records)
        return payload

    return run_audited_tool(
        case_id=case_id,
        tool="disk_recycle_bin",
        args=args,
        iteration=iteration,
        execute=execute,
    )

