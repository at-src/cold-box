"""Windows registry artifact MCP tools."""

from __future__ import annotations

from typing import Any

from postmortem_mcp.artifact_parse import (
    is_placeholder_file,
    load_amcache_with_fallbacks,
    load_json_sidecar,
    parse_evtx_csv_sidecar,
)
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.config import amcache_parser_binary, recmd_binary, scratch_dir
from postmortem_mcp.ez_tools import parse_amcache, parse_registry_hive
from postmortem_mcp.paths import (
    resolve_amcache_path,
    resolve_case_directory,
    resolve_csv_artifact_path,
    resolve_registry_path,
)
from postmortem_mcp.usb_parse import parse_usb_devices


def _csv_tool(
    *,
    case_id: str,
    tool: str,
    artifact_relpath: str,
    iteration: int,
    max_records: int,
    parser_label: str,
    filter_fn=None,
) -> dict:
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_csv_artifact_path(artifact_relpath)
        args["artifact_path"] = str(path)
        payload = load_csv_records(path, max_records=max_records)
        records = payload.get("records") or []
        if filter_fn:
            records = filter_fn(records)
            payload["records"] = records
            payload["record_count"] = len(records)
            payload["returned_count"] = len(records)
        payload["parser"] = parser_label
        return payload

    return run_audited_tool(
        case_id=case_id,
        tool=tool,
        args=args,
        iteration=iteration,
        execute=execute,
    )


def reg_run_keys(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Parse Run/RunOnce registry export for startup persistence."""
    return _csv_tool(
        case_id=case_id,
        tool="reg_run_keys",
        artifact_relpath=artifact_relpath,
        iteration=iteration,
        max_records=max_records,
        parser_label="runkeys-csv",
        filter_fn=lambda rows: [
            row
            for row in rows
            if "run" in str(row.get("KeyPath", "")).lower()
            or "run" in str(row.get("ValueName", "")).lower()
        ],
    )


def reg_services(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 300,
) -> dict:
    """Parse services CSV export for ImagePath / ghost-service triage (R11)."""
    from postmortem_mcp.artifact_parse import parse_services_csv

    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_csv_artifact_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_services_csv(path, max_records=max_records)

    return run_audited_tool(
        case_id=case_id,
        tool="reg_services",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def reg_userassist(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 300,
) -> dict:
    """Parse UserAssist registry export for GUI program execution history."""
    return _csv_tool(
        case_id=case_id,
        tool="reg_userassist",
        artifact_relpath=artifact_relpath,
        iteration=iteration,
        max_records=max_records,
        parser_label="userassist-csv",
    )


def reg_shellbags(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 300,
) -> dict:
    """Parse ShellBags registry export for folder access history."""
    return _csv_tool(
        case_id=case_id,
        tool="reg_shellbags",
        artifact_relpath=artifact_relpath,
        iteration=iteration,
        max_records=max_records,
        parser_label="shellbags-csv",
    )


def reg_amcache(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse Amcache.hve for first-execution records (R2)."""
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_amcache_path(artifact_relpath)
        args["artifact_path"] = str(path)
        sidecar = load_json_sidecar(path, max_records=max_records)
        if sidecar:
            sidecar["parser"] = "amcache-sidecar"
            return sidecar
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
        tool="reg_amcache",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def reg_persistence_sweep(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
    key_path: str | None = None,
    search_string: str | None = None,
) -> dict:
    """Generic registry hive persistence sweep via RECmd (legacy disk_parse_registry path)."""
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
        tool="reg_persistence_sweep",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def disk_parse_usb(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Enumerate USB mass-storage devices from a SYSTEM hive (vendor/product/serial).

    Attributes removable storage (USB sticks) to the host for data-exfil / insider
    triage. Returns each device's vendor, product, serial, friendly name, container
    id, and connection timestamps — every field traceable to its USBSTOR key (R21).
    """
    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        path = resolve_registry_path(artifact_relpath)
        args["artifact_path"] = str(path)
        return parse_usb_devices(path, max_records=max_records)

    return run_audited_tool(
        case_id=case_id,
        tool="disk_parse_usb",
        args=args,
        iteration=iteration,
        execute=execute,
    )
