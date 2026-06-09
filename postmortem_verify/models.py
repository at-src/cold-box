"""Verifier data models."""

from __future__ import annotations

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
    linux_persistence_findings: list[dict[str, Any]] | None = None

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
            linux_persistence_findings=_extract_linux_findings(
                linux_persistence_data, linux_history_data
            ),
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
    return list(events)


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
