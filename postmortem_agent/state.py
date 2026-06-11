"""Investigation state and configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from postmortem_verify.models import RuleResult

RunMode = Literal["autonomous", "llm", "hybrid", "synthetic"]
InvestigationProfile = Literal["autonomous"]


@dataclass
class AgentConfig:
    case_id: str
    evidence_case: str
    memory_relpath: str | None = None
    prefetch_relpath: str | None = None
    amcache_relpath: str | None = None
    mft_relpath: str | None = None
    evtx_relpath: str | None = None
    registry_relpath: str | None = None
    search_root_relpath: str | None = None
    search_patterns: list[str] | None = None
    mode: RunMode = "autonomous"
    profile: InvestigationProfile = "autonomous"
    max_iterations: int = 25
    fixture_dir: Path | None = None
    cache_dir: Path | None = None
    artifact_root: Path | None = None
    extracted_root: Path | None = None
    llm_model: str | None = None
    use_fixtures: bool = False

    def __post_init__(self) -> None:
        if self.mode == "synthetic":
            self.use_fixtures = True
            if self.fixture_dir is None:
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
    hypothesis_authored: bool = False
    survey: dict[str, Any] = field(default_factory=dict)
    lessons: list[str] = field(default_factory=list)
    tool_results: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    verifier_results: list[RuleResult] = field(default_factory=list)
    peak_contradictions: dict[str, RuleResult] = field(default_factory=dict)
    last_notes: str = ""
    llm_transcript: list[dict[str, Any]] = field(default_factory=list)

    def _latest_ok(self, tool: str) -> dict[str, Any] | None:
        runs = self.tool_results.get(tool) or []
        for result in reversed(runs):
            if result.get("ok"):
                return result
        return None

    def _tool_data(self, tool: str) -> dict[str, Any] | None:
        result = self._latest_ok(tool)
        if not result:
            return None
        return result.get("data")

    def pslist_payload(self) -> dict[str, Any] | None:
        return self._tool_data("mem_pslist")

    def psscan_payload(self) -> dict[str, Any] | None:
        return self._tool_data("mem_psscan")

    def security_payload(self) -> dict[str, Any] | None:
        for tool in ("disk_evtx_filter", "disk_parse_evtx"):
            data = self._tool_data(tool)
            if data:
                return data
        return None

    def audit_id(self, tool: str) -> str | None:
        result = self._latest_ok(tool)
        if not result:
            return None
        return result.get("audit_id")

    def all_audit_ids(self) -> list[str]:
        ids: list[str] = []
        seen: set[str] = set()
        for runs in self.tool_results.values():
            for result in runs:
                aid = result.get("audit_id") if result else None
                if aid and aid not in seen:
                    seen.add(aid)
                    ids.append(aid)
        return ids
