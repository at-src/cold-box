"""Senior-analyst compromise bar — no breach declaration on weak R5/R14/R21 alone."""

from __future__ import annotations

from postmortem_agent.findings import build_findings
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.synthesis import (
    compromise_verdict_met,
    confirmed_signals,
    synthesize_hypothesis,
)
from postmortem_verify.known_good import is_benign_uninstall_binary
from postmortem_verify.models import RuleResult, VerifyContext
from postmortem_verify.rules import rule_r5_ghost_binary


def test_avg_prefetch_not_ghost_binary() -> None:
    assert is_benign_uninstall_binary("AVGAM.EXE")
    assert is_benign_uninstall_binary("AVGCSRVX.EXE")
    ctx = VerifyContext(
        prefetch_entries=[{"executable": "AVGAM.EXE"}],
        evidence_basenames={"explorer.exe"},
        prefetch_audit_id="a1",
    )
    result = rule_r5_ghost_binary(ctx)
    assert result.status == "pass"


def test_r5_alone_does_not_meet_compromise_bar() -> None:
    signals = [
        {"rule": "R5", "severity": "high", "title": "Ghost binary", "detail": "prefetch gap"},
        {"rule": "R14", "severity": "medium", "title": "IOC hits", "detail": "27 hits"},
        {"rule": "R21", "severity": "medium", "title": "USB attribution", "detail": "4 USB devices"},
    ]
    assert compromise_verdict_met(signals) is False
    hyp = synthesize_hypothesis(signals, audit_count=12)
    assert "assessed as compromised" not in hyp.lower()
    assert "insider" in hyp.lower() or "physical-access" in hyp.lower()
    assert "not external" in hyp.lower()


def test_usb_alone_stays_generic_restraint() -> None:
    from postmortem_agent.synthesis import classify_scenario

    signals = [
        {"rule": "R21", "severity": "medium", "title": "USB attribution", "detail": "1 device"},
    ]
    assert classify_scenario(signals) == "generic_restraint"
    hyp = synthesize_hypothesis(signals, audit_count=3)
    assert "senior review" in hyp.lower()


def test_r7_meets_compromise_bar() -> None:
    signals = [{"rule": "R7", "severity": "critical", "title": "Injection"}]
    assert compromise_verdict_met(signals) is True
    hyp = synthesize_hypothesis(signals, audit_count=5)
    assert "compromised" in hyp.lower()


def test_weak_signals_use_template_report_not_llm() -> None:
    from postmortem_agent.synthesis import build_llm_report
    from postmortem_agent.state import AgentConfig

    state = InvestigationState(hypothesis="Contradiction detected — revising hypothesis")
    state.verifier_results = [
        RuleResult("R24", "recycle_bin", "contradiction", "0 executables", [{"audit_id": "a1"}]),
        RuleResult("R25", "ie_identity", "contradiction", "inet@microsoft.com", [{"audit_id": "a2"}]),
    ]
    config = AgentConfig(case_id="t", evidence_case=".", mode="llm")
    report = build_llm_report(state, config)
    assert report["source"] == "template"
    assert "well-known" not in report["summary"].lower()
    assert report["attack_chain"]
    assert "senior review" in report["primary_hypothesis"].lower()


def test_weak_signal_combo_findings_and_restraint() -> None:
    state = InvestigationState(hypothesis="Triaging")
    state.verifier_results = [
        RuleResult("R5", "ghost_binary", "contradiction", "prefetch gap", [{"audit_id": "a1"}]),
        RuleResult("R14", "suspicious_ioc", "contradiction", "27 hits", [{"audit_id": "a2"}]),
        RuleResult("R21", "removable_storage", "contradiction", "USB devices", [{"audit_id": "a3"}]),
    ]
    state.tool_results["disk_parse_prefetch"] = [{"ok": True, "audit_id": "a1", "data": {}}]
    findings = build_findings(state, partial=False)
    r5 = [f for f in findings if "R5" in (f.get("tags") or [])]
    assert r5 and r5[0]["status"] == "confirmed"
    r21 = [f for f in findings if "R21" in (f.get("tags") or [])]
    assert r21 and r21[0]["status"] == "confirmed"
    hyp = synthesize_hypothesis(confirmed_signals(state), audit_count=3)
    assert "assessed as compromised" not in hyp.lower()
    assert "insider" in hyp.lower() or "physical-access" in hyp.lower()
