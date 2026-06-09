"""Build verifier context from agent tool results."""

from __future__ import annotations

from pathlib import Path

from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_evidence.guard import resolve_read_path
from postmortem_verify import VerifyContext, run_verifier
from postmortem_verify.models import RuleResult


def build_verify_context(state: InvestigationState, config: AgentConfig) -> VerifyContext:
    evidence_root = _evidence_root(config)

    return VerifyContext.from_tool_payloads(
        pslist_data=state.pslist_payload(),
        psscan_data=state.psscan_payload(),
        amcache_data=_data(state, "disk_parse_amcache"),
        prefetch_data=_prefetch_data(state),
        mft_data=_data(state, "disk_parse_mft"),
        timestomp_data=_data(state, "disk_detect_timestomp"),
        netscan_data=_data(state, "mem_netscan"),
        security_data=state.security_payload(),
        malfind_data=_data(state, "mem_malfind"),
        evtx_data=_data(state, "disk_parse_evtx") or _data(state, "disk_evtx_filter"),
        evidence_root=evidence_root,
        pslist_audit_id=state.audit_id("mem_pslist"),
        psscan_audit_id=state.audit_id("mem_psscan"),
        amcache_audit_id=state.audit_id("disk_parse_amcache"),
        prefetch_audit_id=state.audit_id("disk_parse_prefetch"),
        mft_audit_id=state.audit_id("disk_parse_mft"),
        netscan_audit_id=state.audit_id("mem_netscan"),
        security_audit_id=state.audit_id("disk_evtx_filter") or state.audit_id("disk_parse_evtx"),
        malfind_audit_id=state.audit_id("mem_malfind"),
        evtx_audit_id=state.audit_id("disk_parse_evtx") or state.audit_id("disk_evtx_filter"),
    )


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


def run_lab_verifier(state: InvestigationState, config: AgentConfig) -> list[RuleResult]:
    """Legacy helper for tests migrating to autonomous verifier."""
    return run_verifier(build_verify_context(state, config))
