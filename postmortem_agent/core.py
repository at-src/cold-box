"""Autonomous investigation loop — survey, reason, act, verify, learn."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from postmortem_agent.coverage import build_frontier, coverage_report
from postmortem_agent.diagnostic_memory import (
    hints_from_patterns,
    load_similar_patterns,
    record_case_pattern,
)
from postmortem_agent.findings import build_findings
from postmortem_agent.narrative import append_narrative_finding
from postmortem_agent.synthesis import _is_placeholder, compromise_signals, synthesize_hypothesis
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

# Number of consecutive non-productive iterations (no new verifier signal and no new
# successful tool data) after which the agent concludes instead of spinning. This is
# what keeps a confirmed-evidence case from running to the iteration cap "revising".
STALL_LIMIT = 3
# Substrings that mean an evidence source is simply not present / reachable. Retrying
# the same tool against it wastes iterations, so we record a gap and steer away.
_MISSING_EVIDENCE_MARKERS = (
    "does not exist",
    "pathtraversal",
    "no such file",
    "not found",
    "outside",
)


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

    fired_rules: set[str] = set()
    success_tools: set[str] = set()
    failed_keys: dict[str, str] = {}
    dead_evidence: set[str] = set()
    stall = 0

    _write_progress(state, progress_path, "investigation started — evidence survey complete")

    while not state.done and state.iteration < config.max_iterations:
        state.iteration += 1
        state.phase = "reason"

        # Ingest-first: a raw disk image is useless to the typed parsers until it
        # has been carved into the extracted tree. Force extraction before the
        # reasoner gets a turn so this holds for the policy *and* the LLM brain —
        # an architectural sequence, not a prompt the model can skip.
        forced = _extract_first_action(survey, config, success_tools, failed_keys)
        if forced is not None:
            action = forced
        else:
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
                    budget={"iteration": state.iteration, "max": config.max_iterations},
                    failed_calls=sorted(failed_keys),
                )
            except Exception as exc:
                lesson = f"reasoner error: {exc}"
                state.lessons.append(lesson)
                state.unresolved.append(str(exc))
                _write_progress(state, progress_path, lesson)
                continue

        if action.get("action") == "done":
            candidate = str(action.get("hypothesis", state.hypothesis)).strip()
            if candidate and not _is_placeholder(candidate):
                state.hypothesis = candidate
                state.hypothesis_authored = True
            state.confidence = float(action.get("confidence", state.confidence))
            state.phase = "finalize"
            _write_progress(state, progress_path, "investigation complete — agent declared done")
            break

        tool = str(action.get("tool", "")).strip()
        arguments = action.get("arguments") or {}
        call_key = _call_key(tool, arguments)

        # Failed-call guard: don't burn iterations re-running a call we know fails.
        if call_key in failed_keys:
            stall += 1
            lesson = (
                f"already tried {tool} with these arguments and it failed ({failed_keys[call_key]}); "
                f"do not repeat — choose a different tool or evidence source"
            )
            if lesson not in state.lessons:
                state.lessons.append(lesson)
            _write_progress(state, progress_path, f"skipped repeat of failed call: {tool}",
                            extra={"tool": tool, "reason": action.get("reason")})
            if _should_stop(stall, fired_rules, state=state, survey=survey, config=config):
                break
            continue

        state.phase = "execute"
        result = call_agent_tool(tool, arguments, config=config, iteration=state.iteration)
        result["args"] = arguments
        state.tool_results.setdefault(tool, []).append(result)

        if not result.get("ok"):
            error = str(result.get("error") or "")
            failed_keys[call_key] = error[:120]
            stall += 1
            lesson = f"tool {tool} failed: {error}; try different tool or arguments"
            gap_note = _maybe_record_gap(state, tool, error, dead_evidence)
            if gap_note:
                lesson = gap_note
            if lesson not in state.lessons:
                state.lessons.append(lesson)
            _write_progress(state, progress_path, lesson, extra={"tool": tool, "action": action})
            if _should_stop(stall, fired_rules, state=state, survey=survey, config=config):
                break
            continue

        state.verifier_results = run_verifier(build_verify_context(state, config))
        current_rules = {r.rule_id for r in state.verifier_results if r.status == "contradiction"}
        new_rules = current_rules - fired_rules
        fired_rules |= current_rules

        new_tool_data = tool not in success_tools
        success_tools.add(tool)

        # Extraction just populated EXTRACTED_ROOT — re-survey so the freshly
        # carved hives/EVTX/MFT/prefetch become first-class evidence the typed
        # parsers and the reasoner can now address as ``extracted/<path>``.
        if tool == "disk_extract_image":
            extract_path = case_dir(config.case_id) / "extracted"
            if extract_path.is_dir():
                config.extracted_root = extract_path
                os.environ["EXTRACTED_ROOT"] = str(extract_path.resolve())
            survey = _initial_survey(config)
            state.survey = survey
            pattern_hints = hints_from_patterns(
                load_similar_patterns(survey.get("kinds_present") or [])
            )
        productive = bool(new_rules) or new_tool_data
        stall = 0 if productive else stall + 1

        if new_rules:
            # A new confirmed signal is positive evidence to incorporate — NOT a reason
            # to keep "revising" forever. Record it as a self-correction beat once.
            new_results = [r for r in state.verifier_results if r.rule_id in new_rules]
            lesson = _signal_lesson(new_results)
            if lesson not in state.lessons:
                state.lessons.append(lesson)
            if not state.self_corrected:
                state.self_corrected = True
            state.confidence = min(0.9, max(state.confidence, 0.55) + 0.05 * len(new_rules))
            note = f"self-correction: incorporated new signal(s) {', '.join(sorted(new_rules))}"
        elif current_rules:
            note = f"executed {tool}: corroborates {len(current_rules)} confirmed signal(s)"
        else:
            note = f"executed {tool}: ok (no new signal)"

        if _is_placeholder(state.hypothesis) and current_rules:
            state.hypothesis = _interim_hypothesis(state)
            state.confidence = max(state.confidence, 0.55)
        elif _is_placeholder(state.hypothesis) and result.get("ok"):
            state.hypothesis = f"Triaging {survey.get('kinds_present', [])}; no confirmed signal yet"
            state.confidence = max(state.confidence, 0.45)

        _write_progress(
            state,
            progress_path,
            note,
            extra={
                "tool": tool,
                "audit_id": result.get("audit_id"),
                "reason": action.get("reason"),
                "new_signals": sorted(new_rules),
                "confirmed_signals": sorted(fired_rules),
            },
        )

        if _should_stop(stall, fired_rules, state=state, survey=survey, config=config):
            _write_progress(
                state,
                progress_path,
                f"evidence saturated ({len(fired_rules)} confirmed signal(s), no new signal in "
                f"{STALL_LIMIT} iteration(s)) — concluding",
            )
            break

    partial = not state.done or state.iteration >= config.max_iterations
    _finalize(state, out_dir, progress_path, config=config, partial=partial)
    return state


def _executed_and_failed(state: InvestigationState) -> tuple[set[str], set[str]]:
    executed: set[str] = set()
    failed: set[str] = set()
    for tool, runs in state.tool_results.items():
        for run in runs:
            args = run.get("args") or {}
            key = _call_key(tool, args)
            if run.get("ok"):
                executed.add(key)
            else:
                failed.add(key)
    return executed, failed


def _should_stop(
    stall: int,
    fired_rules: set[str],
    *,
    state: InvestigationState | None = None,
    survey: dict[str, Any] | None = None,
    config: AgentConfig | None = None,
) -> bool:
    """Conclude once evidence is saturated: signals exist and nothing new is surfacing."""
    if stall < STALL_LIMIT or not fired_rules:
        return False
    if state is not None and survey is not None and config is not None:
        executed, failed = _executed_and_failed(state)
        report = coverage_report(survey, config, executed, failed)
        if any(item.priority >= 14 for item in report.pending):
            return False
        if any(item.tool in {"reg_services", "disk_parse_scheduled_tasks"} for item in report.pending):
            return False
    return True


def _extract_first_action(
    survey: dict[str, Any],
    config: AgentConfig,
    success_tools: set[str],
    failed_keys: dict[str, str],
) -> dict[str, Any] | None:
    """Force raw-image extraction before any analysis when an unprocessed image exists.

    Returns ``None`` once extraction has run (or already failed, so we degrade
    gracefully instead of looping) or when there is nothing to extract.
    """
    if "disk_extract_image" in success_tools:
        return None
    if config.extracted_root and config.extracted_root.is_dir():
        return None

    image_relpath: str | None = None
    for entry in survey.get("files") or []:
        if entry.get("kind") == "disk_image":
            image_relpath = entry.get("relpath")
            break
    if not image_relpath:
        return None

    arguments = {"image_relpath": image_relpath}
    if _call_key("disk_extract_image", arguments) in failed_keys:
        return None
    return {
        "action": "tool",
        "tool": "disk_extract_image",
        "arguments": arguments,
        "reason": "raw disk image present → extract artifacts before analysis (ingest-first)",
    }


def _call_key(tool: str, arguments: dict[str, Any]) -> str:
    try:
        return tool + "|" + json.dumps(arguments, sort_keys=True, default=str)
    except TypeError:
        return tool + "|" + str(arguments)


def _maybe_record_gap(
    state: InvestigationState,
    tool: str,
    error: str,
    dead_evidence: set[str],
) -> str | None:
    """Surface an unreachable evidence source as a documented gap (once)."""
    lowered = error.lower()
    if not any(marker in lowered for marker in _MISSING_EVIDENCE_MARKERS):
        return None
    family = tool.split("_", 1)[0]  # mem / disk / web / ...
    if family in dead_evidence:
        return (
            f"{tool} failed again because its evidence source is unavailable; stop probing "
            f"'{family}' artifacts and conclude from what is reachable"
        )
    dead_evidence.add(family)
    gap = f"{family} evidence source unavailable ({error[:80]}) — could not corroborate via {tool}"
    if gap not in state.gaps:
        state.gaps.append(gap)
    return (
        f"{tool} failed: evidence source unavailable. Recorded as an investigation gap; "
        f"do not retry '{family}' tools — corroborate using other evidence"
    )


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


def _signal_lesson(new_results: list[RuleResult]) -> str:
    """Concise, specific note about newly confirmed evidence to fold into the hypothesis."""
    parts = [f"{r.rule_id} ({r.rule_name}): {r.detail}" for r in new_results[:3]]
    return "confirmed signal(s) to incorporate — " + " | ".join(parts)


def _interim_hypothesis(state: InvestigationState) -> str:
    signals = compromise_signals(state)
    return synthesize_hypothesis(signals, audit_count=len(state.all_audit_ids()))


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

    # Never let a placeholder ("Contradiction ... revising") or a partial interim hypothesis
    # survive into the report. Unless the LLM explicitly authored a final conclusion via "done",
    # synthesize one from the COMPLETE set of confirmed signals so the executive summary matches
    # the full narrative.
    compromise = compromise_signals(state)
    if compromise:
        if not state.hypothesis_authored or _is_placeholder(state.hypothesis):
            state.hypothesis = synthesize_hypothesis(compromise, audit_count=len(state.all_audit_ids()))
            state.confidence = max(state.confidence, 0.6)
    else:
        state.hypothesis = synthesize_hypothesis([], audit_count=len(state.all_audit_ids()))
        state.confidence = min(state.confidence, 0.5)

    try:
        state.findings = build_findings(state, partial=partial, config=config)
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
