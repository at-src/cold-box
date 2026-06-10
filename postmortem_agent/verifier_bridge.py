"""Build verifier context from agent tool results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_evidence.guard import resolve_read_path
from postmortem_mcp.timeline import build_super_timeline
from postmortem_verify import VerifyContext, run_verifier
from postmortem_verify.models import RuleResult, _extract_cmdlines, _extract_processes, _extract_records


def build_verify_context(state: InvestigationState, config: AgentConfig) -> VerifyContext:
    evidence_root = _evidence_root(config)
    timeline_data, timeline_audit_id = _resolve_timeline(state)

    ctx = VerifyContext.from_tool_payloads(
        pslist_data=state.pslist_payload(),
        psscan_data=state.psscan_payload(),
        amcache_data=_data(state, "disk_parse_amcache") or _data(state, "reg_amcache"),
        prefetch_data=_prefetch_data(state),
        mft_data=_data(state, "disk_parse_mft"),
        timestomp_data=_data(state, "disk_detect_timestomp"),
        netscan_data=_data(state, "mem_netscan"),
        security_data=state.security_payload(),
        malfind_data=_data(state, "mem_malfind"),
        evtx_data=_data(state, "disk_parse_evtx") or _data(state, "disk_evtx_filter"),
        dns_data=_data(state, "net_dns_extract"),
        http_data=_data(state, "net_http_extract"),
        linux_persistence_data=_data(state, "linux_persistence") or _data(state, "linux_cron"),
        linux_history_data=_data(state, "linux_bash_history"),
        setupapi_data=_data(state, "disk_parse_setupapi"),
        scheduled_task_data=_data(state, "disk_parse_scheduled_tasks"),
        services_data=_data(state, "reg_services"),
        svcscan_data=_data(state, "mem_svcscan"),
        search_data=_data(state, "disk_search_artifacts"),
        timeline_data=timeline_data,
        cmdline_data=_data(state, "mem_cmdline"),
        cmdscan_data=_data(state, "mem_cmdscan"),
        web_access_data=_data(state, "web_parse_access_log"),
        web_inspect_data=_data(state, "web_inspect_artifact"),
        structured_log_data=_data(state, "logs_parse_structured"),
        evidence_root=evidence_root,
        pslist_audit_id=state.audit_id("mem_pslist"),
        psscan_audit_id=state.audit_id("mem_psscan"),
        amcache_audit_id=state.audit_id("disk_parse_amcache") or state.audit_id("reg_amcache"),
        prefetch_audit_id=state.audit_id("disk_parse_prefetch"),
        mft_audit_id=state.audit_id("disk_parse_mft"),
        netscan_audit_id=state.audit_id("mem_netscan"),
        security_audit_id=state.audit_id("disk_evtx_filter") or state.audit_id("disk_parse_evtx"),
        malfind_audit_id=state.audit_id("mem_malfind"),
        evtx_audit_id=state.audit_id("disk_parse_evtx") or state.audit_id("disk_evtx_filter"),
        dns_audit_id=state.audit_id("net_dns_extract"),
        http_audit_id=state.audit_id("net_http_extract"),
        linux_audit_id=state.audit_id("linux_persistence")
        or state.audit_id("linux_bash_history")
        or state.audit_id("linux_cron"),
        setupapi_audit_id=state.audit_id("disk_parse_setupapi"),
        scheduled_task_audit_id=state.audit_id("disk_parse_scheduled_tasks"),
        services_audit_id=state.audit_id("reg_services") or state.audit_id("mem_svcscan"),
        search_audit_id=state.audit_id("disk_search_artifacts"),
        timeline_audit_id=timeline_audit_id,
        cmdline_audit_id=state.audit_id("mem_cmdline") or state.audit_id("mem_cmdscan"),
        web_access_audit_id=state.audit_id("web_parse_access_log"),
        web_inspect_audit_id=state.audit_id("web_inspect_artifact"),
        structured_log_audit_id=state.audit_id("logs_parse_structured"),
    )
    if config.extracted_root and config.extracted_root.is_dir():
        from postmortem_verify.models import evidence_basenames

        extra = evidence_basenames(config.extracted_root)
        if ctx.evidence_basenames:
            ctx.evidence_basenames = ctx.evidence_basenames | extra
        else:
            ctx.evidence_basenames = extra
    return ctx


def _evidence_root(config: AgentConfig) -> Path | None:
    if config.extracted_root:
        return config.extracted_root
    try:
        return resolve_read_path(config.evidence_case).resolve()
    except Exception:
        return None


def _prefetch_data(state: InvestigationState) -> dict | None:
    data = _data(state, "disk_parse_prefetch")
    if data:
        return data
    raw = state._tool_data("disk_parse_prefetch")
    if raw and "prefetch" in raw:
        return raw
    return None


def _data(state: InvestigationState, tool: str) -> dict | None:
    return state._tool_data(tool)


def _timeline_cross_source(data: dict[str, Any] | None) -> bool:
    if not data:
        return False
    events = data.get("events") or []
    by_source = data.get("by_source") or {}
    if len(by_source) >= 2:
        return True
    return len(events) >= 5


def _web_access_records(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if not payload:
        return None
    rows: list[dict[str, Any]] = []
    for key in ("suspicious_requests", "requests"):
        items = payload.get(key)
        if isinstance(items, list):
            rows.extend(item for item in items if isinstance(item, dict))
    return rows or None


def _synthesize_timeline_data(state: InvestigationState) -> dict[str, Any] | None:
    """Merge EVTX, memory, web, and cmdline tool outputs when timeline tools fail or are thin."""
    security = state.security_payload()
    evtx_records = _extract_records(security)
    memory_processes = _extract_processes(state.pslist_payload())
    web_records = _web_access_records(_data(state, "web_parse_access_log"))
    cmdline_records = _extract_cmdlines(_data(state, "mem_cmdline"), _data(state, "mem_cmdscan"))

    if not any([evtx_records, memory_processes, web_records, cmdline_records]):
        return None

    merged = build_super_timeline(
        evtx_records=evtx_records,
        memory_processes=memory_processes,
        web_access_records=web_records,
        cmdline_records=cmdline_records,
    )
    if not _timeline_cross_source(merged):
        return None

    merged["parser"] = "timeline-synthesized"
    return merged


def _resolve_timeline(state: InvestigationState) -> tuple[dict[str, Any] | None, str | None]:
    explicit = _data(state, "timeline_super") or _data(state, "disk_correlate_timeline")
    if explicit and _timeline_cross_source(explicit):
        audit_id = state.audit_id("timeline_super") or state.audit_id("disk_correlate_timeline")
        return explicit, audit_id

    synthesized = _synthesize_timeline_data(state)
    if synthesized:
        audit_id = (
            state.audit_id("disk_evtx_filter")
            or state.audit_id("disk_parse_evtx")
            or state.audit_id("mem_pslist")
            or state.audit_id("web_parse_access_log")
            or state.audit_id("mem_cmdline")
        )
        return synthesized, audit_id

    audit_id = state.audit_id("timeline_super") or state.audit_id("disk_correlate_timeline")
    return explicit, audit_id


def run_lab_verifier(state: InvestigationState, config: AgentConfig) -> list[RuleResult]:
    """Legacy helper for tests migrating to autonomous verifier."""
    return run_verifier(build_verify_context(state, config))
