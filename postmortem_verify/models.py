"""Verifier data models."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

RuleStatus = Literal["pass", "contradiction", "skipped"]


@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    status: RuleStatus
    detail: str
    sources: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerifyContext:
    """Inputs for deterministic verifier rules."""

    pslist_processes: list[dict[str, Any]] | None = None
    psscan_processes: list[dict[str, Any]] | None = None
    amcache_records: list[dict[str, Any]] | None = None
    prefetch_entries: list[dict[str, Any]] | None = None
    mft_records: list[dict[str, Any]] | None = None
    timestomp_findings: list[dict[str, Any]] | None = None
    netscan_connections: list[dict[str, Any]] | None = None
    security_events: list[dict[str, Any]] | None = None
    malfind_findings: list[dict[str, Any]] | None = None
    malfind_finding_count: int = 0
    evtx_records: list[dict[str, Any]] | None = None
    evidence_basenames: set[str] | None = None
    dns_queries: list[dict[str, Any]] | None = None
    http_requests: list[dict[str, Any]] | None = None
    http_periodic: list[dict[str, Any]] | None = None
    web_identities: list[dict[str, Any]] | None = None
    linux_persistence_findings: list[dict[str, Any]] | None = None
    setupapi_devices: list[dict[str, Any]] | None = None
    scheduled_tasks: list[dict[str, Any]] | None = None
    service_entries: list[dict[str, Any]] | None = None
    search_hits: list[dict[str, Any]] | None = None
    timeline_events: list[dict[str, Any]] | None = None
    cmdline_entries: list[dict[str, Any]] | None = None
    web_suspicious_requests: list[dict[str, Any]] | None = None
    web_artifact_indicators: list[dict[str, Any]] | None = None
    structured_log_events: list[dict[str, Any]] | None = None
    usb_devices: list[dict[str, Any]] | None = None
    exfil_hits: list[dict[str, Any]] | None = None
    yara_matches: list[dict[str, Any]] | None = None
    linux_memory_probe: dict[str, Any] | None = None
    android_probe: dict[str, Any] | None = None
    android_findings: list[dict[str, Any]] | None = None
    macos_probe: dict[str, Any] | None = None
    macos_findings: list[dict[str, Any]] | None = None

    pslist_audit_id: str | None = None
    psscan_audit_id: str | None = None
    amcache_audit_id: str | None = None
    prefetch_audit_id: str | None = None
    mft_audit_id: str | None = None
    netscan_audit_id: str | None = None
    security_audit_id: str | None = None
    malfind_audit_id: str | None = None
    evtx_audit_id: str | None = None
    dns_audit_id: str | None = None
    http_audit_id: str | None = None
    linux_audit_id: str | None = None
    setupapi_audit_id: str | None = None
    scheduled_task_audit_id: str | None = None
    services_audit_id: str | None = None
    timeline_audit_id: str | None = None
    search_audit_id: str | None = None
    cmdline_audit_id: str | None = None
    web_access_audit_id: str | None = None
    web_inspect_audit_id: str | None = None
    structured_log_audit_id: str | None = None
    usb_audit_id: str | None = None
    exfil_audit_id: str | None = None
    yara_audit_id: str | None = None
    linux_memory_audit_id: str | None = None
    android_audit_id: str | None = None
    macos_audit_id: str | None = None

    pslist_source: str | None = None
    psscan_source: str | None = None
    amcache_source: str | None = None
    prefetch_source: str | None = None
    mft_source: str | None = None
    netscan_source: str | None = None
    security_source: str | None = None
    dns_source: str | None = None
    http_source: str | None = None
    linux_source: str | None = None
    usb_source: str | None = None
    exfil_source: str | None = None
    yara_source: str | None = None
    linux_memory_source: str | None = None
    android_source: str | None = None
    macos_source: str | None = None

    timestomp_tolerance_seconds: int = 1

    @classmethod
    def from_tool_payloads(
        cls,
        *,
        pslist_data: dict[str, Any] | None = None,
        psscan_data: dict[str, Any] | None = None,
        amcache_data: dict[str, Any] | None = None,
        prefetch_data: dict[str, Any] | None = None,
        mft_data: dict[str, Any] | None = None,
        netscan_data: dict[str, Any] | None = None,
        timestomp_data: dict[str, Any] | None = None,
        security_data: dict[str, Any] | None = None,
        malfind_data: dict[str, Any] | None = None,
        evtx_data: dict[str, Any] | None = None,
        dns_data: dict[str, Any] | None = None,
        http_data: dict[str, Any] | None = None,
        linux_persistence_data: dict[str, Any] | None = None,
        linux_history_data: dict[str, Any] | None = None,
        setupapi_data: dict[str, Any] | None = None,
        scheduled_task_data: dict[str, Any] | None = None,
        services_data: dict[str, Any] | None = None,
        svcscan_data: dict[str, Any] | None = None,
        search_data: dict[str, Any] | None = None,
        timeline_data: dict[str, Any] | None = None,
        cmdline_data: dict[str, Any] | None = None,
        cmdscan_data: dict[str, Any] | None = None,
        web_access_data: dict[str, Any] | None = None,
        web_inspect_data: dict[str, Any] | None = None,
        structured_log_data: dict[str, Any] | None = None,
        usb_data: dict[str, Any] | None = None,
        exfil_data: dict[str, Any] | None = None,
        yara_data: dict[str, Any] | None = None,
        linux_memory_data: dict[str, Any] | None = None,
        android_probe_data: dict[str, Any] | None = None,
        android_scan_data: dict[str, Any] | None = None,
        macos_probe_data: dict[str, Any] | None = None,
        macos_scan_data: dict[str, Any] | None = None,
        evidence_root: str | Path | None = None,
        pslist_audit_id: str | None = None,
        psscan_audit_id: str | None = None,
        amcache_audit_id: str | None = None,
        prefetch_audit_id: str | None = None,
        mft_audit_id: str | None = None,
        netscan_audit_id: str | None = None,
        security_audit_id: str | None = None,
        malfind_audit_id: str | None = None,
        evtx_audit_id: str | None = None,
        dns_audit_id: str | None = None,
        http_audit_id: str | None = None,
        linux_audit_id: str | None = None,
        setupapi_audit_id: str | None = None,
        scheduled_task_audit_id: str | None = None,
        services_audit_id: str | None = None,
        timeline_audit_id: str | None = None,
        search_audit_id: str | None = None,
        cmdline_audit_id: str | None = None,
        web_access_audit_id: str | None = None,
        web_inspect_audit_id: str | None = None,
        structured_log_audit_id: str | None = None,
        usb_audit_id: str | None = None,
        exfil_audit_id: str | None = None,
        yara_audit_id: str | None = None,
        linux_memory_audit_id: str | None = None,
        android_audit_id: str | None = None,
        macos_audit_id: str | None = None,
        timestomp_tolerance_seconds: int = 1,
    ) -> VerifyContext:
        mft_records = _extract_mft_records(mft_data)
        timestomp_findings = _extract_timestomp_findings(timestomp_data)

        basenames = None
        if evidence_root is not None:
            basenames = evidence_basenames(Path(evidence_root))

        return cls(
            pslist_processes=_extract_processes(pslist_data),
            psscan_processes=_extract_processes(psscan_data),
            amcache_records=_extract_records(amcache_data),
            prefetch_entries=_extract_prefetch(prefetch_data),
            mft_records=mft_records,
            timestomp_findings=timestomp_findings,
            netscan_connections=_extract_connections(netscan_data),
            security_events=_extract_security_events(security_data),
            malfind_findings=_extract_malfind(malfind_data),
            malfind_finding_count=int((malfind_data or {}).get("finding_count") or 0),
            evtx_records=_extract_records(evtx_data),
            evidence_basenames=basenames,
            dns_queries=_extract_dns_queries(dns_data),
            http_requests=_extract_http_requests(http_data),
            http_periodic=_extract_http_periodic(http_data),
            web_identities=_extract_web_identities(http_data),
            linux_persistence_findings=_extract_linux_findings(
                linux_persistence_data, linux_history_data
            ),
            setupapi_devices=_extract_setupapi(setupapi_data),
            scheduled_tasks=_extract_scheduled_tasks(scheduled_task_data),
            service_entries=_extract_services(services_data, svcscan_data),
            search_hits=_extract_search_hits(search_data),
            timeline_events=_extract_timeline_events(timeline_data),
            cmdline_entries=_extract_cmdlines(cmdline_data, cmdscan_data),
            web_suspicious_requests=_extract_web_suspicious(web_access_data),
            web_artifact_indicators=_extract_web_indicators(web_inspect_data),
            structured_log_events=_extract_structured_flagged(structured_log_data),
            usb_devices=_extract_usb(usb_data),
            exfil_hits=_extract_exfil_hits(exfil_data),
            yara_matches=_extract_yara_matches(yara_data),
            linux_memory_probe=_extract_linux_memory_probe(linux_memory_data),
            android_probe=_extract_android_probe(android_probe_data),
            android_findings=_extract_android_findings(android_scan_data),
            macos_probe=_extract_macos_probe(macos_probe_data),
            macos_findings=_extract_macos_findings(macos_scan_data),
            pslist_audit_id=pslist_audit_id,
            psscan_audit_id=psscan_audit_id,
            amcache_audit_id=amcache_audit_id,
            prefetch_audit_id=prefetch_audit_id,
            mft_audit_id=mft_audit_id or (timestomp_data or {}).get("audit_id"),
            netscan_audit_id=netscan_audit_id,
            security_audit_id=security_audit_id,
            malfind_audit_id=malfind_audit_id,
            evtx_audit_id=evtx_audit_id,
            dns_audit_id=dns_audit_id,
            http_audit_id=http_audit_id,
            linux_audit_id=linux_audit_id or (linux_persistence_data or {}).get("audit_id"),
            setupapi_audit_id=setupapi_audit_id or (setupapi_data or {}).get("audit_id"),
            scheduled_task_audit_id=scheduled_task_audit_id
            or (scheduled_task_data or {}).get("audit_id"),
            services_audit_id=services_audit_id
            or (services_data or svcscan_data or {}).get("audit_id"),
            timeline_audit_id=timeline_audit_id or (timeline_data or {}).get("audit_id"),
            search_audit_id=search_audit_id or (search_data or {}).get("audit_id"),
            cmdline_audit_id=cmdline_audit_id
            or (cmdline_data or cmdscan_data or {}).get("audit_id"),
            web_access_audit_id=web_access_audit_id or (web_access_data or {}).get("audit_id"),
            web_inspect_audit_id=web_inspect_audit_id or (web_inspect_data or {}).get("audit_id"),
            structured_log_audit_id=structured_log_audit_id
            or (structured_log_data or {}).get("audit_id"),
            usb_audit_id=usb_audit_id or (usb_data or {}).get("audit_id"),
            exfil_audit_id=exfil_audit_id or (exfil_data or {}).get("audit_id"),
            yara_audit_id=yara_audit_id or (yara_data or {}).get("audit_id"),
            linux_memory_audit_id=linux_memory_audit_id
            or (linux_memory_data or {}).get("audit_id"),
            android_audit_id=android_audit_id
            or (android_scan_data or android_probe_data or {}).get("audit_id"),
            macos_audit_id=macos_audit_id
            or (macos_scan_data or macos_probe_data or {}).get("audit_id"),
            pslist_source=(pslist_data or {}).get("source"),
            psscan_source=(psscan_data or {}).get("source"),
            amcache_source=(amcache_data or {}).get("source"),
            prefetch_source=(prefetch_data or {}).get("source"),
            mft_source=(mft_data or timestomp_data or {}).get("source"),
            netscan_source=(netscan_data or {}).get("source"),
            security_source=(security_data or {}).get("source"),
            dns_source=(dns_data or {}).get("source"),
            http_source=(http_data or {}).get("source"),
            linux_source=(linux_persistence_data or linux_history_data or {}).get("source"),
            usb_source=(usb_data or {}).get("source"),
            exfil_source=(exfil_data or {}).get("source"),
            yara_source=(yara_data or {}).get("source"),
            linux_memory_source=(linux_memory_data or {}).get("source"),
            android_source=(android_scan_data or android_probe_data or {}).get("source"),
            macos_source=(macos_scan_data or macos_probe_data or {}).get("source"),
            timestomp_tolerance_seconds=timestomp_tolerance_seconds,
        )


def evidence_basenames(root: Path) -> set[str]:
    names: set[str] = set()
    if not root.is_dir():
        return names
    for path in root.rglob("*"):
        if path.is_file():
            names.add(path.name.lower())
    return names


def _extract_processes(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    processes = payload.get("processes")
    if processes is None:
        processes = payload.get("rows")
    if processes is None:
        return None
    return list(processes)


def _extract_records(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    records = payload.get("records")
    if records is None and "data" in payload:
        nested = payload["data"]
        if isinstance(nested, dict):
            records = nested.get("records")
    if records is None:
        return None
    return list(records)


def _extract_prefetch(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    if "prefetch" in payload:
        return [payload["prefetch"]]
    if "executables" in payload:
        items = payload["executables"]
        return list(items) if isinstance(items, list) else None
    if "executable" in payload:
        return [{"executable": payload["executable"], "source": payload.get("source")}]
    return None


def _extract_mft_records(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    records = payload.get("records")
    if records is not None:
        return list(records)
    return None


def _extract_timestomp_findings(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    findings = payload.get("findings")
    if isinstance(findings, list):
        return list(findings)
    return None


def _extract_timestomp_rows_as_mft(payload: dict[str, Any]) -> list[dict[str, Any]] | None:
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return None
    rows: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        if "path" in row and "FileName" not in row:
            row["FullPath"] = row["path"]
        rows.append(row)
    return rows or None


def _extract_malfind(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    findings = payload.get("findings")
    if isinstance(findings, list) and findings:
        return list(findings)
    count = payload.get("finding_count") or payload.get("row_count")
    if count:
        return [{"finding_count": count}]
    return None


def _extract_dns_queries(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    queries = payload.get("queries")
    if isinstance(queries, list):
        return list(queries)
    top = payload.get("top_domains")
    if isinstance(top, list):
        return [{"query": row.get("domain"), "count": row.get("count")} for row in top]
    return None


def _extract_http_requests(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    requests = payload.get("requests")
    if isinstance(requests, list):
        return list(requests)
    return None


def _extract_http_periodic(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    periodic = payload.get("periodic_same_size")
    if isinstance(periodic, list):
        return list(periodic)
    return None


def _extract_web_identities(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    identities = payload.get("identities")
    if isinstance(identities, list):
        return list(identities)
    return None


def _extract_linux_findings(
    persistence: dict[str, Any] | None,
    history: dict[str, Any] | None,
) -> list[dict[str, Any]] | None:
    rows: list[dict[str, Any]] = []
    if persistence:
        findings = persistence.get("findings")
        if isinstance(findings, list):
            rows.extend(findings)
        entries = persistence.get("entries")
        if isinstance(entries, list):
            rows.extend(entries)
    if history:
        hits = history.get("hits")
        if isinstance(hits, list):
            rows.extend(hits)
    return rows or None


def _extract_search_hits(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    hits = payload.get("hits")
    if isinstance(hits, list):
        return list(hits)
    return None


def _extract_timeline_events(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    events = payload.get("events")
    if isinstance(events, list):
        return list(events)
    return None


def _extract_cmdlines(
    cmdline_data: dict[str, Any] | None,
    cmdscan_data: dict[str, Any] | None,
) -> list[dict[str, Any]] | None:
    rows: list[dict[str, Any]] = []
    for payload in (cmdline_data, cmdscan_data):
        if not payload:
            continue
        for key in ("cmdlines", "records", "processes", "rows"):
            items = payload.get(key)
            if isinstance(items, list):
                rows.extend(item for item in items if isinstance(item, dict))
    return rows or None


def _extract_web_suspicious(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    hits = payload.get("suspicious_requests")
    if isinstance(hits, list):
        return list(hits)
    return None


def _extract_web_indicators(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    indicators = payload.get("indicators")
    if isinstance(indicators, list) and indicators:
        return list(indicators)
    if payload.get("suspicious"):
        return [{"path": payload.get("path"), "snippet": "webshell indicators present"}]
    return None


def _extract_structured_flagged(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    flagged = payload.get("flagged_events")
    if isinstance(flagged, list) and flagged:
        return list(flagged)
    return None


def _extract_usb(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    records = payload.get("records")
    if records is None and isinstance(payload.get("data"), dict):
        records = payload["data"].get("records")
    if isinstance(records, list) and records:
        return list(records)
    return None


def _extract_exfil_hits(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    hits = payload.get("hits")
    if isinstance(hits, list) and hits:
        return list(hits)
    return None


def _extract_yara_matches(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    matches = payload.get("matches")
    if isinstance(matches, list) and matches:
        return list(matches)
    return None


def _extract_linux_memory_probe(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    if payload.get("parser") == "linux-memory-probe" or "isf_gap" in payload:
        return dict(payload)
    return None


def _extract_android_probe(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    if payload.get("parser") == "android-probe":
        return dict(payload)
    return None


def _extract_android_findings(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    findings = payload.get("findings")
    if isinstance(findings, list) and findings:
        return list(findings)
    notes = payload.get("acquisition_notes")
    if isinstance(notes, list) and notes:
        return list(notes)
    return None


def _extract_macos_probe(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    if payload.get("parser") == "macos-probe":
        return dict(payload)
    return None


def _extract_macos_findings(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    findings = payload.get("findings")
    if isinstance(findings, list) and findings:
        return list(findings)
    return None


def _extract_setupapi(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    suspicious = payload.get("suspicious_devices")
    if isinstance(suspicious, list) and suspicious:
        return list(suspicious)
    records = payload.get("records")
    if isinstance(records, list):
        flagged = [row for row in records if isinstance(row, dict) and row.get("suspicious_kvm")]
        return flagged or list(records)
    return None


def _extract_scheduled_tasks(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    records = payload.get("records")
    if isinstance(records, list):
        return list(records)
    if payload.get("task_name"):
        return [payload]
    return None


def _extract_services(
    services_data: dict[str, Any] | None,
    svcscan_data: dict[str, Any] | None,
) -> list[dict[str, Any]] | None:
    from postmortem_mcp.artifact_parse import normalize_service_binary

    rows: list[dict[str, Any]] = []
    if services_data:
        records = services_data.get("records")
        if isinstance(records, list):
            rows.extend(records)
    if svcscan_data:
        services = svcscan_data.get("services")
        if isinstance(services, list):
            for svc in services:
                if not isinstance(svc, dict):
                    continue
                binary = svc.get("Binary") or svc.get("ImagePath") or svc.get("Path") or ""
                rows.append(
                    {
                        "name": svc.get("Name") or svc.get("Service") or "?",
                        "binary": binary,
                        "binary_basename": normalize_service_binary(str(binary)),
                        "source": "mem_svcscan",
                    }
                )
    return rows or None


def _extract_security_events(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    events = payload.get("events")
    if events is None:
        records = payload.get("records")
        if isinstance(records, list):
            events = records
    if events is None:
        return None
    normalized: list[dict[str, Any]] = []
    for row in events:
        if not isinstance(row, dict):
            continue
        if "event_id" in row:
            normalized.append(row)
            continue
        eid_raw = row.get("EventId") or row.get("Event ID") or row.get("Id") or 0
        try:
            event_id = int(eid_raw)
        except (TypeError, ValueError):
            event_id = 0
        payload_text = " ".join(
            str(row.get(key, ""))
            for key in ("PayloadData1", "PayloadData2", "PayloadData3", "Payload")
        )
        logon_type = row.get("LogonType")
        if logon_type is None and "LogonType" in payload_text:
            for token in payload_text.replace(",", " ").split():
                if token.startswith("LogonType"):
                    try:
                        logon_type = int(token.split("LogonType", 1)[1].strip())
                    except ValueError:
                        pass
                    break
        session_id = row.get("SessionId") or row.get("TargetLogonId")
        if session_id is None and "LogonId:" in payload_text:
            for part in payload_text.split(","):
                if "LogonId:" in part:
                    session_id = part.split("LogonId:", 1)[1].strip()
                    break
        normalized.append(
            {
                "event_id": event_id,
                "time_created": row.get("TimeCreated") or row.get("Timestamp"),
                "user": row.get("UserName") or row.get("TargetUserName"),
                "logon_type": logon_type,
                "session_id": session_id,
                "raw": row,
            }
        )
    return normalized


def _extract_connections(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    connections = payload.get("connections")
    if connections is None:
        connections = payload.get("rows")
    if connections is None:
        return None
    return list(connections)


def _connection_pid(row: dict[str, Any]) -> int | None:
    raw = row.get("pid", row.get("PID"))
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None
