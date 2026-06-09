"""Deterministic and profile-driven investigation loops."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from postmortem_agent.progress import append_progress, progress_log_path
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.tools import invoke_tool
from postmortem_agent.verifier_bridge import build_verify_context, run_lab_verifier
from postmortem_mcp.config import case_dir
from postmortem_report.gate import validate_findings
from postmortem_report.report import write_report
from postmortem_verify import run_verifier
from postmortem_verify.models import RuleResult


@dataclass
class _Step:
    phase: str
    tool: str
    fixture: str | None = None


R1_PLAN = [
    _Step("triage", "evidence_manifest"),
    _Step("hypothesis", "mem_pslist"),
    _Step("validate", "mem_psscan"),
]

LAB_DISK_STEPS = [
    _Step("disk", "disk_parse_prefetch"),
    _Step("disk", "disk_detect_timestomp"),
    _Step("disk", "mem_netscan"),
    _Step("disk", "security_events"),
    _Step("disk", "disk_correlate_timeline"),
    _Step("validate", "mem_pslist", "r3-pslist.json"),
]


def run_investigation(config: AgentConfig) -> InvestigationState:
    if config.mode == "llm":
        from postmortem_agent.live import run_llm_investigation

        return run_llm_investigation(config)

    state = InvestigationState()
    out_dir = case_dir(config.case_id)
    progress_path = progress_log_path(out_dir)

    if config.profile == "lab":
        return _run_lab_profile(state, config, out_dir, progress_path)
    if config.profile == "ali-hadi":
        from postmortem_agent.ali_hadi import run_ali_hadi_profile

        return run_ali_hadi_profile(state, config, out_dir, progress_path)
    return _run_r1_profile(state, config, out_dir, progress_path)


def _run_r1_profile(
    state: InvestigationState,
    config: AgentConfig,
    out_dir: Path,
    progress_path: Path,
) -> InvestigationState:
    plan_index = 0
    awaiting_self_correction = False

    while not state.done and state.iteration < config.max_iterations:
        state.iteration += 1

        if awaiting_self_correction:
            _run_self_correction(state, config, progress_path)
            awaiting_self_correction = False
            _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=False)
            continue

        if plan_index >= len(R1_PLAN):
            _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=False)
            break

        step = R1_PLAN[plan_index]
        state.phase = step.phase
        result = invoke_tool(
            step.tool,
            config=config,
            iteration=state.iteration,
            fixture_override=step.fixture,
        )
        state.tool_results[step.tool] = result

        notes = f"executed {step.tool}: ok={result.get('ok')}"
        if not result.get("ok"):
            state.unresolved.append(f"{step.tool} failed: {result.get('error', 'unknown')}")
            state.confidence = max(0.1, state.confidence - 0.2)
            notes = f"tool failure on {step.tool}"

        if step.phase == "hypothesis" and result.get("ok"):
            state.hypothesis = "Windows service processes appear benign (svchost baseline)"
            state.confidence = 0.6
            notes = "initial hypothesis from mem_pslist"

        if step.phase == "validate" and result.get("ok"):
            notes = _run_verifier_r1(state, config)
            r1 = _rule(state, "R1")
            if r1 and r1.status == "contradiction":
                state.unresolved.append(f"R1 hidden_process: {r1.detail}")
                state.confidence = 0.4
                notes = "self-correction: R1 hidden_process fired; scheduling mem_cmdline"
                awaiting_self_correction = True
                _write_progress(state, progress_path, notes)
                plan_index += 1
                continue

        _write_progress(state, progress_path, notes)
        plan_index += 1

    if not state.done:
        state.last_notes = "max-iterations reached; partial closeout"
        _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=True)

    return state


def _run_lab_profile(
    state: InvestigationState,
    config: AgentConfig,
    out_dir: Path,
    progress_path: Path,
) -> InvestigationState:
    config.prefetch_relpath = config.prefetch_relpath or "disk/Windows/Prefetch/COLDLOADER.EXE-B1C2D3E4.pf"
    config.mft_relpath = config.mft_relpath or "disk/$MFT.csv"

    plan = list(R1_PLAN)
    awaiting_self_correction = False
    plan_index = 0
    post_r1 = False

    while not state.done and state.iteration < config.max_iterations:
        state.iteration += 1

        if awaiting_self_correction:
            _run_self_correction(state, config, progress_path)
            awaiting_self_correction = False
            post_r1 = True
            plan_index = 0
            continue

        if post_r1:
            if plan_index >= len(LAB_DISK_STEPS):
                state.verifier_results = run_lab_verifier(state, config)
                notes = _summarize_verifier(state)
                _write_progress(state, progress_path, notes)
                _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=False)
                break
            step = LAB_DISK_STEPS[plan_index]
        else:
            if plan_index >= len(plan):
                break
            step = plan[plan_index]

        state.phase = step.phase
        if step.tool == "disk_parse_prefetch":
            result = invoke_tool(step.tool, config=config, iteration=state.iteration)
        elif step.tool == "disk_detect_timestomp":
            result = invoke_tool(step.tool, config=config, iteration=state.iteration)
        elif step.tool == "disk_correlate_timeline":
            saved_evtx = config.evtx_relpath
            config.evtx_relpath = None
            result = invoke_tool(step.tool, config=config, iteration=state.iteration)
            config.evtx_relpath = saved_evtx
        elif step.tool == "security_events":
            result = invoke_tool(
                "security_events",
                config=config,
                iteration=state.iteration,
                fixture_override="r3-security.json",
            )
        else:
            result = invoke_tool(
                step.tool,
                config=config,
                iteration=state.iteration,
                fixture_override=step.fixture,
            )
        state.tool_results[step.tool] = result

        notes = f"executed {step.tool}: ok={result.get('ok')}"
        if step.phase == "hypothesis" and result.get("ok"):
            state.hypothesis = "Operator workstation looks routine; low suspicion"
            state.confidence = 0.55

        if not post_r1 and step.phase == "validate" and result.get("ok"):
            notes = _run_verifier_r1(state, config)
            r1 = _rule(state, "R1")
            if r1 and r1.status == "contradiction":
                state.confidence = 0.35
                notes = "self-correction: R1 fired before disk correlation"
                awaiting_self_correction = True
                _write_progress(state, progress_path, notes)
                plan_index += 1
                continue

        _write_progress(state, progress_path, notes)
        plan_index += 1

    if not state.done:
        _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=True)
    return state


def _run_verifier_r1(state: InvestigationState, config: AgentConfig) -> str:
    ctx = build_verify_context(state, config)
    state.verifier_results = [run_verifier(ctx)[0]]
    r1 = state.verifier_results[0]
    if r1.status == "pass":
        state.hypothesis = "No hidden-process contradiction between pslist and psscan"
        state.confidence = 0.75
        return "verifier R1 pass"
    if r1.status == "skipped":
        return f"verifier R1 skipped: {r1.detail}"
    return f"verifier R1 contradiction: {r1.detail}"


def _run_self_correction(
    state: InvestigationState,
    config: AgentConfig,
    progress_path: Path,
) -> None:
    state.phase = "self_correction"
    result = invoke_tool("mem_cmdline", config=config, iteration=state.iteration)
    state.tool_results["mem_cmdline"] = result
    state.self_corrected = True
    state.hypothesis = (
        "Hidden/unlinked process in psscan absent from pslist; cmdline evidence collected"
    )
    state.confidence = 0.88
    state.unresolved = [u for u in state.unresolved if not u.startswith("R1 hidden_process:")]
    notes = "self-correction: hypothesis revised after R1 contradiction and mem_cmdline"
    state.last_notes = notes
    _write_progress(state, progress_path, notes)


def _rule(state: InvestigationState, rule_id: str) -> RuleResult | None:
    for result in state.verifier_results:
        if result.rule_id == rule_id:
            return result
    return None


def _summarize_verifier(state: InvestigationState) -> str:
    contradictions = [r.rule_id for r in state.verifier_results if r.status == "contradiction"]
    if contradictions:
        return f"verifier contradictions: {', '.join(contradictions)}"
    return "verifier pass on all rules with inputs present"


def _write_progress(state: InvestigationState, progress_path: Path, notes: str) -> None:
    state.last_notes = notes
    append_progress(
        progress_path,
        iteration=state.iteration,
        phase=state.phase,
        hypothesis=state.hypothesis,
        confidence=state.confidence,
        unresolved=state.unresolved,
        notes=notes,
    )


def _finalize(
    state: InvestigationState,
    out_dir: Path,
    progress_path: Path,
    *,
    case_id: str,
    partial: bool,
) -> None:
    state.phase = "finalize"
    state.done = True
    raw_findings = _build_findings(state, partial=partial)
    state.findings = validate_findings(raw_findings)
    findings_path = out_dir / "findings.json"
    findings_path.write_text(
        json.dumps({"findings": state.findings}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_report(out_dir, case_id=case_id)
    notes = "investigation finalized"
    if partial:
        notes = "partial closeout at max-iterations"
    if state.self_corrected:
        notes = "self-correction: investigation finalized after verifier-driven follow-up"
    _write_progress(state, progress_path, notes)


def _build_findings(state: InvestigationState, *, partial: bool) -> list[dict[str, Any]]:
    audit_ids = state.all_audit_ids()
    findings: list[dict[str, Any]] = []
    idx = 1

    if state.self_corrected:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": state.hypothesis,
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "confirmed",
                "tags": ["R1", "self-correction"],
            }
        )
        idx += 1

    rule_claims = {
        "R3": "Successful logon events lack matching memory session (phantom logon)",
        "R4": "MFT timestomp anomaly detected on disk",
        "R5": "Prefetch references executable missing from evidence tree",
        "R6": "Network connection owned by PID absent from pslist",
        "R2": "Process in memory without disk execution trail",
    }

    for result in state.verifier_results:
        if result.status != "contradiction":
            continue
        claim = rule_claims.get(result.rule_id, result.detail)
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": claim,
                "audit_ids": audit_ids,
                "confidence": 0.85,
                "status": "confirmed",
                "tags": [result.rule_id, result.rule_name],
            }
        )
        idx += 1

    if not findings and state.verifier_results:
        r1 = _rule(state, "R1")
        if r1 and r1.status == "pass":
            findings.append(
                {
                    "id": "f-1",
                    "claim": state.hypothesis,
                    "audit_ids": audit_ids,
                    "confidence": state.confidence,
                    "status": "confirmed",
                    "tags": ["R1"],
                }
            )

    for uidx, item in enumerate(state.unresolved, start=1):
        findings.append(
            {
                "id": f"u-{uidx}",
                "claim": item,
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "unresolved",
            }
        )

    if partial and not findings:
        findings.append(
            {
                "id": "u-0",
                "claim": "Investigation incomplete at iteration limit",
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "unresolved",
            }
        )

    return findings
