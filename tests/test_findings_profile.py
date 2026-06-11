"""Tests for host-profile and content context findings."""

from __future__ import annotations

from postmortem_agent.findings import build_findings
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_verify.models import RuleResult


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


def test_web_attack_finding_on_webserver_case_with_r7() -> None:
    state = InvestigationState(
        hypothesis="Web server compromised",
        survey={
            "kinds_present": ["disk_image", "memory_image"],
            "files": [{"relpath": "Case1-Webserver.E01", "kind": "disk_image"}],
        },
    )
    state.verifier_results = [
        RuleResult("R7", "memory_injection", "contradiction", "injected region", [])
    ]
    state.tool_results["mem_malfind"] = [{"ok": True, "audit_id": "malf-1", "data": {"finding_count": 1}}]
    config = AgentConfig(case_id="ali-hadi-1", evidence_case="ali-hadi-1")
    findings = build_findings(state, partial=False, config=config)
    web = [f for f in findings if "AH-1" in f.get("tags", [])]
    assert web
    assert "apache" in web[0]["claim"].lower() or "web" in web[0]["claim"].lower()


def test_restraint_case_demotes_timeline_and_emits_no_confirmed() -> None:
    state = InvestigationState(hypothesis="Host assessed as compromised")
    state.verifier_results = [
        RuleResult(
            "R15",
            "timeline_correlation",
            "contradiction",
            "Cross-source timeline: 20 event(s) from evtx=19",
            [{"audit_id": "tl-1"}],
        )
    ]
    state.tool_results["timeline_super"] = [{"ok": True, "audit_id": "tl-1", "data": {}}]
    findings = build_findings(state, partial=False)
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    assert len(confirmed) == 1
    assert "no confirmed indicators" in confirmed[0]["claim"].lower()
    context = [f for f in findings if f.get("status") == "context"]
    assert any("timeline" in f.get("claim", "").lower() for f in context)
