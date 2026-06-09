"""Investigation state and configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from postmortem_verify.models import RuleResult

AgentMode = Literal["live", "synthetic"]


@dataclass
class AgentConfig:
    case_id: str
    evidence_case: str
    memory_relpath: str | None = None
    mode: AgentMode = "live"
    max_iterations: int = 10
    fixture_dir: Path | None = None

    def __post_init__(self) -> None:
        if self.mode == "synthetic" and self.fixture_dir is None:
            self.fixture_dir = Path("examples/sample-verifier")


@dataclass
class InvestigationState:
    hypothesis: str = "Investigation not started"
    confidence: float = 0.5
    unresolved: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    phase: str = "triage"
    iteration: int = 0
    done: bool = False
    self_corrected: bool = False
    tool_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    verifier_results: list[RuleResult] = field(default_factory=list)
    last_notes: str = ""

    def pslist_payload(self) -> dict[str, Any] | None:
        return self._tool_data("mem_pslist")

    def psscan_payload(self) -> dict[str, Any] | None:
        return self._tool_data("mem_psscan")

    def _tool_data(self, tool: str) -> dict[str, Any] | None:
        result = self.tool_results.get(tool)
        if not result or not result.get("ok"):
            return None
        return result.get("data")

    def audit_id(self, tool: str) -> str | None:
        result = self.tool_results.get(tool)
        if not result:
            return None
        return result.get("audit_id")
