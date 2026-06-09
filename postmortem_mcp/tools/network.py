"""Network capture MCP tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.pcap_parse import (
    extract_conversations,
    extract_dns_queries,
    extract_http_hosts,
    summarize_pcap,
)
from postmortem_mcp.paths import resolve_pcap_path


def _load_sidecar(path: Path, suffix: str) -> dict[str, Any] | None:
    sidecar = path.parent / f"{path.name}.{suffix}"
    if sidecar.is_file():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return None


def net_pcap_summary(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_packets: int = 5000,
) -> dict:
    """Summarize packet counts and protocols in a PCAP/PCAPNG file."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_packets": max_packets}

    def execute() -> dict[str, Any]:
        path = resolve_pcap_path(artifact_relpath)
        args["artifact_path"] = str(path)
        sidecar = _load_sidecar(path, "summary.json")
        if sidecar:
            sidecar.setdefault("source", str(path))
            return sidecar
        return summarize_pcap(path, max_packets=max_packets)

    return run_audited_tool(case_id=case_id, tool="net_pcap_summary", args=args, iteration=iteration, execute=execute)


def net_dns_extract(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Extract DNS queries from a PCAP for exfil/tunneling triage."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        path = resolve_pcap_path(artifact_relpath)
        args["artifact_path"] = str(path)
        sidecar = _load_sidecar(path, "dns.json")
        if sidecar:
            sidecar.setdefault("source", str(path))
            return sidecar
        return extract_dns_queries(path, max_records=max_records)

    return run_audited_tool(case_id=case_id, tool="net_dns_extract", args=args, iteration=iteration, execute=execute)


def net_http_extract(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Extract HTTP Host headers and same-size POST patterns from PCAP."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        path = resolve_pcap_path(artifact_relpath)
        args["artifact_path"] = str(path)
        sidecar = _load_sidecar(path, "http.json")
        if sidecar:
            sidecar.setdefault("source", str(path))
            return sidecar
        return extract_http_hosts(path, max_records=max_records)

    return run_audited_tool(case_id=case_id, tool="net_http_extract", args=args, iteration=iteration, execute=execute)


def net_conversations(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Rank IP:port conversation pairs by packet count."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        path = resolve_pcap_path(artifact_relpath)
        args["artifact_path"] = str(path)
        sidecar = _load_sidecar(path, "conv.json")
        if sidecar:
            sidecar.setdefault("source", str(path))
            return sidecar
        return extract_conversations(path, max_records=max_records)

    return run_audited_tool(case_id=case_id, tool="net_conversations", args=args, iteration=iteration, execute=execute)
