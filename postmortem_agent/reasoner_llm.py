"""LLM reasoner — role and constraints only, no scripted method."""

from __future__ import annotations

import json
from typing import Any, Protocol

from postmortem_agent.llm import LLMError, decide_next_action, static_system_block
from postmortem_agent.state import AgentConfig


SYSTEM_PROMPT = """You are a senior DFIR analyst investigating a dead host.
You are given an evidence survey, tool catalog, and optional pattern hints from past cases.
Choose ONE next action per turn as JSON. Decide order yourself from what the evidence shows.

A deterministic verifier runs after every tool. Each "confirmed_signal" it reports is REAL,
audited evidence of compromise to INCORPORATE into your hypothesis — not a reason to doubt
yourself indefinitely. Pursue NEW leads (skipped rules, follow-ups on a fresh signal); do not
re-run tools that already succeeded or that already failed (see failed_calls).

Converge like a senior analyst: once the confirmed signals form a coherent compromise story and
new tools stop surfacing new signals, return "done" with a complete hypothesis (initial access →
execution → persistence → C2 → exfil as applicable). Do NOT keep investigating once evidence is
saturated or your iteration budget is nearly spent. Never claim a finding no tool produced.
Respond with a single JSON object only — no markdown fences, no prose before or after.

Actions:
{"action":"tool","tool":"<name>","arguments":{...},"reason":"<short>"}
{"action":"done","hypothesis":"<full attack-chain summary>","confidence":0.0-1.0}
"""


class LLMReasoner:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.messages: list[dict[str, Any]] = []
        self._system: str | list[dict[str, Any]] | None = None
        self._survey_snapshot: dict[str, Any] | None = None

    def _system_payload(self, catalog: dict[str, Any]) -> str | list[dict[str, Any]]:
        """Static system + tool catalog cached across turns (Anthropic prompt caching)."""
        if self._system is not None:
            return self._system
        tools = catalog.get("tools") if isinstance(catalog, dict) else catalog
        static = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Tool catalog JSON (choose only these tools):\n"
            f"{json.dumps(tools, sort_keys=True)}"
        )
        self._system = static_system_block(static)
        return self._system

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
        budget: dict[str, Any] | None = None,
        failed_calls: list[str] | None = None,
        **_ignored: Any,
    ) -> dict[str, Any]:
        if self._survey_snapshot is None:
            self._survey_snapshot = {
                "kinds_present": survey.get("kinds_present"),
                "file_count": survey.get("file_count"),
                "files": (survey.get("files") or [])[:40],
            }

        # Compact verifier view: confirmed signals (no bulky `sources` arrays — those
        # were re-sent every turn and dominated token cost) + counts of open/skipped rules.
        confirmed = [
            {"rule": r.rule_id, "name": r.rule_name, "detail": str(r.detail)[:160]}
            for r in verifier
            if getattr(r, "status", None) == "contradiction"
        ]
        skipped = [r.rule_id for r in verifier if getattr(r, "status", None) == "skipped"]

        context: dict[str, Any] = {
            "hypothesis": hypothesis,
            "lessons": lessons[-6:],
            "tools_run": _summarize_results(results),
            "confirmed_signals": confirmed,
            "open_rules": skipped,
        }
        if budget:
            context["budget"] = budget
        if failed_calls:
            context["do_not_repeat"] = failed_calls[-12:]
        if not self.messages:
            context["goal"] = goal
            context["instruction"] = "Begin investigation."
            context["survey_summary"] = self._survey_snapshot
            context["skills"] = skills
            context["pattern_hints"] = pattern_hints
        else:
            context["turn"] = len(self.messages) // 2 + 1

        self.messages.append({"role": "user", "content": json.dumps(context, sort_keys=True)})

        action = decide_next_action(
            system=self._system_payload(catalog),
            messages=self.messages,
            model=self.config.llm_model,
        )
        self.messages.append({"role": "assistant", "content": json.dumps(action, sort_keys=True)})
        return action


def _summarize_results(results: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for tool, runs in results.items():
        last = runs[-1] if runs else {}
        summary.append(
            {
                "tool": tool,
                "ok": last.get("ok"),
                "runs": len(runs),
                "error": (str(last.get("error"))[:80] if last.get("error") else None),
            }
        )
    return summary


class Reasoner(Protocol):
    def decide(self, **kwargs: Any) -> dict[str, Any]: ...
