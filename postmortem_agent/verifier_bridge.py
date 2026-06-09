"""Build verifier context from agent tool results."""

from __future__ import annotations

import json
from pathlib import Path

from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_verify import VerifyContext, run_verifier
from postmortem_verify.models import RuleResult


def build_verify_context(state: InvestigationState, config: AgentConfig) -> VerifyContext:
    evidence_root = None
    if config.profile == "lab":
        evidence_root = Path("examples/sample-evidence").resolve()
    elif config.extracted_root:
        evidence_root = config.extracted_root

    return VerifyContext.from_tool_payloads(
        pslist_data=state.pslist_payload(),
        psscan_data=state.psscan_payload(),
        amcache_data=_data(state, "disk_parse_amcache"),
        prefetch_data=_data(state, "disk_parse_prefetch"),
        mft_data=_data(state, "disk_parse_mft"),
        timestomp_data=_data(state, "disk_detect_timestomp"),
        netscan_data=_data(state, "mem_netscan"),
        security_data=state.security_payload(),
        malfind_data=_data(state, "mem_malfind"),
        evtx_data=_data(state, "disk_parse_evtx"),
        evidence_root=evidence_root,
        pslist_audit_id=state.audit_id("mem_pslist"),
        psscan_audit_id=state.audit_id("mem_psscan"),
        amcache_audit_id=state.audit_id("disk_parse_amcache"),
        prefetch_audit_id=state.audit_id("disk_parse_prefetch"),
        mft_audit_id=state.audit_id("disk_parse_mft"),
        netscan_audit_id=state.audit_id("mem_netscan"),
        security_audit_id=state.audit_id("security_events"),
        malfind_audit_id=state.audit_id("mem_malfind"),
        evtx_audit_id=state.audit_id("disk_parse_evtx"),
    )


def _rule_result(ctx: VerifyContext, rule_id: str) -> RuleResult:
    return next(result for result in run_verifier(ctx) if result.rule_id == rule_id)


def run_lab_verifier(state: InvestigationState, config: AgentConfig) -> list[RuleResult]:
    """Run rules with fixture-specific inputs where the lab playbook requires them."""
    assert config.fixture_dir is not None
    root = Path("examples/sample-evidence").resolve()

    def load(name: str) -> dict:
        return json.loads((config.fixture_dir / name).read_text(encoding="utf-8"))

    by_id = {result.rule_id: result for result in run_verifier(build_verify_context(state, config))}

    by_id["R3"] = _rule_result(
        VerifyContext.from_tool_payloads(
            pslist_data=load("r3-pslist.json"),
            security_data=load("r3-security.json"),
            pslist_audit_id=state.audit_id("mem_pslist"),
            security_audit_id=state.audit_id("security_events"),
        ),
        "R3",
    )
    by_id["R5"] = _rule_result(
        VerifyContext.from_tool_payloads(
            prefetch_data=load("r5-prefetch.json"),
            evidence_root=root,
            prefetch_audit_id=state.audit_id("disk_parse_prefetch"),
        ),
        "R5",
    )
    by_id["R6"] = _rule_result(
        VerifyContext.from_tool_payloads(
            pslist_data=load("r6-pslist.json"),
            netscan_data=_data(state, "mem_netscan"),
            pslist_audit_id=state.audit_id("mem_pslist"),
            netscan_audit_id=state.audit_id("mem_netscan"),
        ),
        "R6",
    )

    return [by_id[f"R{i}"] for i in range(1, 8) if f"R{i}" in by_id]


def _data(state: InvestigationState, tool: str) -> dict | None:
    result = state.tool_results.get(tool)
    if not result or not result.get("ok"):
        return None
    return result.get("data")
