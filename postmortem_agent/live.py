"""LLM-driven investigation loop with verifier-injected self-correction."""

from __future__ import annotations

import json
from typing import Any

from postmortem_agent.llm import LLMError, decide_next_action
from postmortem_agent.loop import _finalize, _write_progress
from postmortem_agent.progress import progress_log_path
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.tools import invoke_tool
from postmortem_agent.verifier_bridge import build_verify_context
from postmortem_mcp.config import case_dir
from postmortem_mcp.dispatch import list_tools
from postmortem_verify import run_verifier

SYSTEM_PROMPT = """You are a senior DFIR analyst investigating a dead Windows host.
You may ONLY choose tools from the provided list. Respond with JSON only.

Actions:
{"action":"tool","tool":"<name>","reason":"<short>"}
{"action":"done","hypothesis":"<summary>","confidence":0.0-1.0}

Method: triage manifest → memory processes → cross-check with verifier rules.
When the verifier reports a contradiction, run a follow-up tool before finishing.
Never invent findings — only cite tools you ran."""


def run_llm_investigation(config: AgentConfig) -> InvestigationState:
    state = InvestigationState()
    out_dir = case_dir(config.case_id)
    progress_path = progress_log_path(out_dir)
    tools = list_tools()
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": json.dumps(
                {
                    "case_id": config.case_id,
                    "evidence_case": config.evidence_case,
                    "memory": config.memory_relpath,
                    "available_tools": tools,
                    "instruction": "Begin investigation. Pick the first tool.",
                }
            ),
        }
    ]

    while not state.done and state.iteration < config.max_iterations:
        state.iteration += 1
        try:
            action = decide_next_action(system=SYSTEM_PROMPT, messages=messages, model=config.llm_model)
        except LLMError as exc:
            state.unresolved.append(str(exc))
            state.last_notes = f"LLM error: {exc}"
            _write_progress(state, progress_path, state.last_notes)
            break

        state.llm_transcript.append({"iteration": state.iteration, "action": action})

        if action.get("action") == "done":
            state.hypothesis = str(action.get("hypothesis", state.hypothesis))
            state.confidence = float(action.get("confidence", state.confidence))
            state.phase = "finalize"
            _write_progress(state, progress_path, "LLM declared investigation complete")
            break

        tool = str(action.get("tool", "")).strip()
        if tool not in tools:
            note = f"LLM requested unknown tool {tool!r}; retry"
            messages.append({"role": "assistant", "content": json.dumps(action)})
            messages.append({"role": "user", "content": note})
            _write_progress(state, progress_path, note)
            continue

        state.phase = "execute"
        try:
            result = invoke_tool(tool, config=config, iteration=state.iteration)
        except RuntimeError as exc:
            note = f"tool {tool} failed: {exc}"
            messages.append({"role": "assistant", "content": json.dumps(action)})
            messages.append({"role": "user", "content": note})
            _write_progress(state, progress_path, note)
            continue

        state.tool_results[tool] = result
        state.verifier_results = run_verifier(build_verify_context(state, config))
        contradictions = [r.to_dict() for r in state.verifier_results if r.status == "contradiction"]

        if contradictions and not state.self_corrected:
            state.self_corrected = True
            state.confidence = max(0.3, state.confidence - 0.2)
            note = "self-correction: verifier contradiction detected; continuing investigation"
        else:
            note = f"executed {tool}; verifier ok={not contradictions}"

        feedback = {
            "tool": tool,
            "ok": result.get("ok"),
            "audit_id": result.get("audit_id"),
            "verifier": [r.to_dict() for r in state.verifier_results],
            "contradictions": contradictions,
        }
        messages.append({"role": "assistant", "content": json.dumps(action)})
        messages.append({"role": "user", "content": json.dumps(feedback)})
        _write_progress(state, progress_path, note)

    if not state.done:
        _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=state.iteration >= config.max_iterations)
    else:
        state.verifier_results = run_verifier(build_verify_context(state, config))
        _finalize(state, out_dir, progress_path, case_id=config.case_id, partial=False)

    transcript_path = out_dir / "llm_transcript.json"
    transcript_path.write_text(json.dumps(state.llm_transcript, indent=2) + "\n", encoding="utf-8")
    return state
