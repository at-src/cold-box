"""Hybrid reasoner — LLM ordering with a deterministic policy coverage floor."""

from __future__ import annotations

from typing import Any

from postmortem_agent.reasoner_llm import LLMReasoner
from postmortem_agent.reasoner_policy import (
    policy_block_llm_done,
    policy_coverage_floor,
    sync_tool_attempts,
)
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
        executed, failed = sync_tool_attempts(results)

        floor = policy_coverage_floor(
            verifier=verifier,
            results=results,
            survey=survey,
            config=self.config,
            executed=executed,
            failed=failed,
        )
        if floor is not None:
            return floor

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

        if action.get("action") == "done":
            block = policy_block_llm_done(
                verifier=verifier,
                results=results,
                survey=survey,
                config=self.config,
                executed=executed,
                failed=failed,
            )
            if block is not None:
                return block

        return action
