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
    """Parse services from a CSV export or SYSTEM hive for ghost-service triage (R11)."""
    from postmortem_mcp.artifact_parse import parse_services_csv
    from postmortem_mcp.services_parse import parse_services_hive

    args = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "max_records": max_records,
    }

    def execute() -> dict[str, Any]:
        if artifact_relpath.lower().endswith(".csv"):
            path = resolve_csv_artifact_path(artifact_relpath)
            args["artifact_path"] = str(path)
            return parse_services_csv(path, max_records=max_records)
        path = resolve_registry_path(artifact_relpath)
        args["artifact_path"] = str(path)
        # SYSTEM hives typically hold 600+ services; enumerate enough for R11.
        hive_cap = max(max_records, 2000)
        return parse_services_hive(path, max_records=hive_cap)

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


def reg_query(
    case_id: str,
    artifact_relpath: str,
    key_path: str,
    *,
    value_name: str | None = None,
    iteration: int = 0,
) -> dict:
    """Read an arbitrary registry key/value from a hive (read-only, python-registry).

    Generic value extraction for content-centric questions (host attribution,
    system state) that the artifact-specific parsers do not cover.
    """
    from postmortem_mcp.registry_query import query_value

    args: dict[str, Any] = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "key_path": key_path,
        "value_name": value_name,
    }

    def execute() -> dict[str, Any]:
        path = resolve_registry_path(artifact_relpath)
        args["artifact_path"] = str(path)
        result = query_value(path, key_path, value_name)
        result["parser"] = "python-registry"
        result["source"] = str(path)
        return result

    return run_audited_tool(
        case_id=case_id,
        tool="reg_query",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def reg_system_profile(
    case_id: str,
    artifact_relpath: str,
    *,
    system_relpath: str | None = None,
    sam_relpath: str | None = None,
    iteration: int = 0,
) -> dict:
    """Extract a host-attribution / system-state profile from SOFTWARE (+ SYSTEM + SAM) hives.

    Surfaces registered owner/org, OS product, install date, computer name,
    installed network cards, last shutdown time, and local accounts (primary
    user + logon count) — every fact traceable to its hive via the audit chain.
    ``artifact_relpath`` is the SOFTWARE hive; ``system_relpath`` (optional) is
    the SYSTEM hive; ``sam_relpath`` (optional) is the SAM hive.
    """
    from postmortem_mcp.registry_query import system_profile

    args: dict[str, Any] = {
        "case_id": case_id,
        "artifact_relpath": artifact_relpath,
        "system_relpath": system_relpath,
        "sam_relpath": sam_relpath,
    }

    def execute() -> dict[str, Any]:
        software_path = resolve_registry_path(artifact_relpath)
        args["software_path"] = str(software_path)
        system_path = None
        if system_relpath:
            system_path = resolve_registry_path(system_relpath)
            args["system_path"] = str(system_path)
        sam_path = None
        if sam_relpath:
            sam_path = resolve_registry_path(sam_relpath)
            args["sam_path"] = str(sam_path)
        profile = system_profile(software=software_path, system=system_path, sam=sam_path)
        profile["parser"] = "python-registry"
        profile["fact_count"] = len(profile.get("facts", []))
        return profile

    return run_audited_tool(
        case_id=case_id,
        tool="reg_system_profile",
        args=args,
        iteration=iteration,
        execute=execute,
    )
