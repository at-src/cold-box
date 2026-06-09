"""Deterministic investigation loop (scripted phases, no LLM)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from postmortem_agent.progress import append_progress, progress_log_path
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.tools import invoke_tool
from postmortem_mcp.config import case_dir
from postmortem_report.gate import validate_findings
from postmortem_report.report import write_report
from postmortem_verify import VerifyContext, run_verifier


@dataclass
class _Step:
    phase: str
    tool: str


DEFAULT_PLAN = [
    _Step("triage", "evidence_manifest"),
    _Step("hypothesis", "mem_pslist"),
    _Step("validate", "mem_psscan"),
]


def run_investigation(config: AgentConfig) -> InvestigationState:
    state = InvestigationState()
    out_dir = case_dir(config.case_id)
    progress_path = progress_log_path(out_dir)

    plan_index = 0
    awaiting_self_correction = False

    while not state.done and state.iteration < config.max_iterations:
        state.iteration += 1

        if awaiting_self_correction:
            _run_self_correction(state, config, progress_path)
            awaiting_self_correction = False
            _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=False)
            continue

        if plan_index >= len(DEFAULT_PLAN):
            _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=False)
            break

        step = DEFAULT_PLAN[plan_index]
        state.phase = step.phase
        result = invoke_tool(step.tool, config=config, iteration=state.iteration)
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
            notes = _run_verifier(state)
            r1 = state.verifier_results[0] if state.verifier_results else None
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


def _run_verifier(state: InvestigationState) -> str:
    ctx = VerifyContext.from_tool_payloads(
        pslist_data=state.pslist_payload(),
        psscan_data=state.psscan_payload(),
        pslist_audit_id=state.audit_id("mem_pslist"),
        psscan_audit_id=state.audit_id("mem_psscan"),
    )
    state.verifier_results = run_verifier(ctx)
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
    state.confidence = 0.9
    state.unresolved = [item for item in state.unresolved if not item.startswith("R1 hidden_process:")]
    notes = "self-correction: hypothesis revised after R1 contradiction and mem_cmdline"
    state.last_notes = notes
    _write_progress(state, progress_path, notes)


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
    findings: list[dict[str, Any]] = []
    audit_ids = [
        aid
        for tool in ("evidence_manifest", "mem_pslist", "mem_psscan", "mem_cmdline")
        if (aid := state.audit_id(tool))
    ]

    if state.self_corrected:
        findings.append(
            {
                "id": "f-1",
                "claim": state.hypothesis,
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "confirmed",
            }
        )
    elif state.verifier_results and state.verifier_results[0].status == "pass":
        findings.append(
            {
                "id": "f-1",
                "claim": state.hypothesis,
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "confirmed",
            }
        )

    for idx, item in enumerate(state.unresolved, start=1):
        findings.append(
            {
                "id": f"u-{idx}",
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
