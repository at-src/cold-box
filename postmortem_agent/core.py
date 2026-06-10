"""Autonomous investigation loop — survey, reason, act, verify, learn."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from postmortem_agent.diagnostic_memory import (
    hints_from_patterns,
    load_similar_patterns,
    record_case_pattern,
)
from postmortem_agent.findings import build_findings
from postmortem_agent.narrative import append_narrative_finding
from postmortem_agent.invoke import call_agent_tool
from postmortem_agent.progress import append_progress, progress_log_path
from postmortem_agent.reasoner import load_skill_index, make_reasoner
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.verifier_bridge import build_verify_context
from postmortem_mcp.catalog import catalog_as_dict
from postmortem_mcp.config import case_dir
from postmortem_mcp.survey import (
    build_survey_payload,
    evidence_survey,
    merge_extracted_survey,
    synthetic_survey,
)
from postmortem_report.report import write_report
from postmortem_verify import run_verifier
from postmortem_verify.models import RuleResult

GOAL = "Find evidence of compromise on this dead host and explain it."


def run_investigation(config: AgentConfig) -> InvestigationState:
    import os

    state = InvestigationState()
    out_dir = case_dir(config.case_id)
    progress_path = progress_log_path(out_dir)
    reasoner = make_reasoner(config)
    skills = load_skill_index()

    if config.extracted_root:
        os.environ["EXTRACTED_ROOT"] = str(config.extracted_root.expanduser().resolve())

    survey = _initial_survey(config)
    state.survey = survey
    pattern_hints = hints_from_patterns(load_similar_patterns(survey.get("kinds_present") or []))
    catalog_payload = catalog_as_dict()

    _write_progress(state, progress_path, "investigation started — evidence survey complete")

    while not state.done and state.iteration < config.max_iterations:
        state.iteration += 1
        state.phase = "reason"

        try:
            action = reasoner.decide(
                goal=GOAL,
                survey=survey,
                catalog={"tools": catalog_payload},
                skills=skills,
                results=state.tool_results,
                verifier=state.verifier_results,
                hypothesis=state.hypothesis,
                lessons=state.lessons,
                pattern_hints=pattern_hints,
            )
        except Exception as exc:
            state.unresolved.append(str(exc))
            _write_progress(state, progress_path, f"reasoner error: {exc}")
            break

        if action.get("action") == "done":
            state.hypothesis = str(action.get("hypothesis", state.hypothesis))
            state.confidence = float(action.get("confidence", state.confidence))
            state.phase = "finalize"
            _write_progress(state, progress_path, "investigation complete — agent declared done")
            break

        tool = str(action.get("tool", "")).strip()
        arguments = action.get("arguments") or {}
        state.phase = "execute"
        result = call_agent_tool(tool, arguments, config=config, iteration=state.iteration)
        result["args"] = arguments
        state.tool_results.setdefault(tool, []).append(result)

        if not result.get("ok"):
            lesson = f"tool {tool} failed: {result.get('error')}; try different tool or arguments"
            state.lessons.append(lesson)
            _write_progress(
                state,
                progress_path,
                lesson,
                extra={"tool": tool, "action": action},
            )
            continue

        state.verifier_results = run_verifier(build_verify_context(state, config))
        contradictions = [r for r in state.verifier_results if r.status == "contradiction"]

        if contradictions:
            lesson = _lesson_from(contradictions, action)
            if lesson not in state.lessons:
                state.lessons.append(lesson)
            if not state.self_corrected:
                state.self_corrected = True
                state.confidence = max(0.3, state.confidence - 0.15)
            rules = ", ".join(r.rule_id for r in contradictions)
            state.hypothesis = f"Contradiction {rules} — revising understanding before concluding"
            note = f"self-correction: {lesson}"
        else:
            note = f"executed {tool}: ok={result.get('ok')}"

        if result.get("ok") and state.hypothesis == "Investigation not started":
            state.hypothesis = f"Analyzing {survey.get('kinds_present', [])} — no contradictions yet"
            state.confidence = 0.45

        _write_progress(
            state,
            progress_path,
            note,
            extra={
                "tool": tool,
                "audit_id": result.get("audit_id"),
                "reason": action.get("reason"),
                "lessons": list(state.lessons),
            },
        )

    partial = not state.done or state.iteration >= config.max_iterations
    _finalize(state, out_dir, progress_path, config=config, partial=partial)
    return state


def _initial_survey(config: AgentConfig) -> dict[str, Any]:
    if config.mode == "synthetic" and config.fixture_dir:
        from postmortem_agent.invoke import FIXTURE_MAP

        payload = synthetic_survey(config.evidence_case, FIXTURE_MAP)
        result = call_agent_tool(
            "evidence_survey",
            {"case_relpath": config.evidence_case},
            config=config,
            iteration=0,
        )
        if result.get("ok"):
            return result.get("data") or payload
        return payload

    try:
        result = evidence_survey(config.case_id, config.evidence_case, iteration=0)
        if result.get("ok"):
            payload = result["data"]
            if config.extracted_root and config.extracted_root.is_dir():
                payload = merge_extracted_survey(
                    payload, config.extracted_root.expanduser().resolve()
                )
            return payload
    except Exception:
        pass

    try:
        from postmortem_mcp.paths import resolve_case_directory

        case_root = resolve_case_directory(config.evidence_case)
        payload = build_survey_payload(case_root, config.evidence_case)
        if config.extracted_root and config.extracted_root.is_dir():
            payload = merge_extracted_survey(payload, config.extracted_root.expanduser().resolve())
        return payload
    except Exception:
        return synthetic_survey(config.evidence_case, {})


def _lesson_from(contradictions: list[RuleResult], action: dict[str, Any]) -> str:
    rules = ", ".join(r.rule_id for r in contradictions)
    tool = action.get("tool", "?")
    return (
        f"verifier {rules} contradicts current understanding after {tool}; "
        f"revise hypothesis and run follow-up tools before concluding"
    )


def _write_progress(
    state: InvestigationState,
    progress_path: Path,
    notes: str,
    *,
    extra: dict[str, Any] | None = None,
) -> None:
    state.last_notes = notes
    append_progress(
        progress_path,
        iteration=state.iteration,
        phase=state.phase,
        hypothesis=state.hypothesis,
        confidence=state.confidence,
        unresolved=state.unresolved,
        notes=notes,
        extra=extra,
    )


def _finalize(
    state: InvestigationState,
    out_dir: Path,
    progress_path: Path,
    *,
    config: AgentConfig,
    partial: bool,
) -> None:
    state.phase = "finalize"
    state.done = True
    state.verifier_results = run_verifier(build_verify_context(state, config))

    try:
        state.findings = build_findings(state, partial=partial)
    except ValueError:
        state.findings = []

    narrative_payload = None
    if state.findings:
        try:
            narrative_payload = append_narrative_finding(state, config)
        except Exception:
            narrative_payload = None

    if state.findings:
        findings_path = out_dir / "findings.json"
        findings_path.write_text(
            json.dumps({"findings": state.findings}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if narrative_payload:
            (out_dir / "narrative.md").write_text(
                narrative_payload.get("text", "") + "\n",
                encoding="utf-8",
            )
        write_report(out_dir, case_id=config.case_id)

    record_case_pattern(
        kinds_present=state.survey.get("kinds_present") or [],
        tools_run=list(state.tool_results.keys()),
        rules_fired=[r.rule_id for r in state.verifier_results if r.status == "contradiction"],
        lessons=list(state.lessons),
        iterations=state.iteration,
        self_corrected=state.self_corrected,
    )

    note = "investigation finalized"
    if partial:
        note = "partial closeout at max-iterations"
    if state.self_corrected:
        note = "self-correction: investigation finalized after verifier-driven follow-up"
    _write_progress(state, progress_path, note)
