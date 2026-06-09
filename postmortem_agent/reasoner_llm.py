"""LLM reasoner — role and constraints only, no scripted method."""

from __future__ import annotations

import json
from typing import Any, Protocol

from postmortem_agent.llm import LLMError, decide_next_action
from postmortem_agent.state import AgentConfig


SYSTEM_PROMPT = """You are a senior DFIR analyst investigating a dead host.
You are given an evidence survey, tool catalog, and optional pattern hints from past cases.
Choose ONE next action per turn as JSON. Decide order yourself from what the evidence shows.
When the verifier reports a contradiction, investigate it before concluding.
Never claim a finding you did not produce with a tool. Stop when the evidence supports a coherent explanation.

Actions:
{"action":"tool","tool":"<name>","arguments":{...},"reason":"<short>"}
{"action":"done","hypothesis":"<summary>","confidence":0.0-1.0}
"""


class LLMReasoner:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.messages: list[dict[str, Any]] = []

    def decide(
        self,
        *,
        goal: str,
        survey: dict[str, Any],
        catalog: dict[str, Any],
        skills: list[dict[str, Any]],
        results: dict[str, list[dict[str, Any]]],
        verifier: list[Any],
        hypothesis: str,
        lessons: list[str],
        pattern_hints: list[str],
    ) -> dict[str, Any]:
        context = {
            "goal": goal,
            "survey_summary": {
                "kinds_present": survey.get("kinds_present"),
                "file_count": survey.get("file_count"),
                "files": (survey.get("files") or [])[:40],
            },
            "catalog": catalog.get("tools") if isinstance(catalog, dict) else catalog,
            "skills": skills,
            "pattern_hints": pattern_hints,
            "hypothesis": hypothesis,
            "lessons": lessons,
            "tools_run": _summarize_results(results),
            "verifier": [r.to_dict() if hasattr(r, "to_dict") else r for r in verifier],
        }
        if not self.messages:
            self.messages.append(
                {"role": "user", "content": json.dumps({"instruction": "Begin investigation.", **context})}
            )
        else:
            self.messages.append({"role": "user", "content": json.dumps(context)})

        action = decide_next_action(
            system=SYSTEM_PROMPT,
            messages=self.messages,
            model=self.config.llm_model,
        )
        self.messages.append({"role": "assistant", "content": json.dumps(action)})
        return action


def _summarize_results(results: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for tool, runs in results.items():
        last = runs[-1] if runs else {}
        summary.append(
            {
                "tool": tool,
                "ok": last.get("ok"),
                "audit_id": last.get("audit_id"),
                "error": last.get("error"),
            }
        )
    return summary


class Reasoner(Protocol):
    def decide(self, **kwargs: Any) -> dict[str, Any]: ...
