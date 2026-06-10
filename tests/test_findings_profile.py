"""Tests for host-profile and content context findings."""

from __future__ import annotations

from postmortem_agent.findings import build_findings
from postmortem_agent.state import InvestigationState


def test_host_profile_finding_from_reg_system_profile() -> None:
    state = InvestigationState(hypothesis="Triaging")
    state.tool_results["reg_system_profile"] = [
        {
            "ok": True,
            "audit_id": "audit-1",
            "data": {
                "facts": [
                    {"label": "Registered owner", "value": "Greg Schardt"},
                    {"label": "Primary user account", "value": "Mr. Evil"},
                ]
            },
        }
    ]
    findings = build_findings(state, partial=False)
    profile = [f for f in findings if f.get("status") == "context" and "host_profile" in f.get("tags", [])]
    assert profile
    assert "Greg Schardt" in profile[0]["claim"]
