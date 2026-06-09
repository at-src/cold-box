"""Investigation entry — autonomous core only."""

from __future__ import annotations

from postmortem_agent.core import run_investigation
from postmortem_agent.state import AgentConfig, InvestigationState

__all__ = ["AgentConfig", "InvestigationState", "run_investigation"]
