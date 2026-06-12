"""Hybrid reasoner — LLM ordering with a deterministic policy coverage floor."""

from __future__ import annotations

from typing import Any

from postmortem_agent.reasoner_llm import LLMReasoner
from postmortem_agent.state import AgentConfig


class HybridReasoner:
    """Run mandatory coverage tools first; let the LLM handle everything else."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._llm = LLMReasoner(config)

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
        **kwargs: Any,
    ) -> dict[str, Any]:
        action = self._llm.decide(
            goal=goal,
            survey=survey,
            catalog=catalog,
            skills=skills,
            results=results,
            verifier=verifier,
            hypothesis=hypothesis,
            lessons=lessons,
            pattern_hints=pattern_hints,
            **kwargs,
        )
        return action
