"""Scoring harness tests."""

from __future__ import annotations

from pathlib import Path

from postmortem_agent.scoring import load_ground_truth, score_findings

REPO = Path(__file__).resolve().parents[1]


def test_score_dart_ground_truth_full_recall() -> None:
    gt = load_ground_truth(REPO / "ground-truth" / "dart-sample-evidence.json")
    findings = [
        {
            "id": "f-1",
            "claim": "IP-KVM/diagnostic USB inserted (USB\\VID_0557&PID_2419)",
            "tags": ["R12", "usb_initial_access"],
            "status": "confirmed",
        },
        {
            "id": "f-2",
            "claim": "Unusual binary execution: remote-admin.exe",
            "tags": ["R16", "unusual_execution"],
            "status": "confirmed",
        },
        {
            "id": "f-3",
            "claim": "1 suspicious scheduled task(s) (RemoteHandsSync",
            "tags": ["R13", "scheduled_task"],
            "status": "confirmed",
        },
        {
            "id": "f-4",
            "claim": "Web compromise: 22 attack request(s) and 1 webshell indicator(s)",
            "tags": ["R19", "web_attack"],
            "status": "confirmed",
        },
    ]
    report = score_findings(findings, gt, self_corrected=True)
    assert report.required_recall >= 1.0
    assert "F-001" not in report.missed
    assert "F-002" not in report.missed
    assert "F-003" not in report.missed


def test_score_ali_partial() -> None:
    gt = load_ground_truth(REPO / "ground-truth" / "ali-hadi-1.json")
    findings = [
        {
            "id": "f-1",
            "claim": "1 injected/RWX memory region(s) detected by malfind",
            "tags": ["R7", "memory_injection"],
            "status": "confirmed",
        },
        {
            "id": "f-2",
            "claim": "2 suspicious command-line artifact(s) (cmd.exe",
            "tags": ["R18", "cmd_leftover"],
            "status": "confirmed",
        },
    ]
    report = score_findings(findings, gt, self_corrected=False)
    assert report.required_recall < 1.0
    assert "AH-1" in report.missed or "AH-6" in report.missed


def test_required_findings_matched_before_optional() -> None:
    gt = load_ground_truth(REPO / "ground-truth" / "ali-hadi-1.json")
    findings = [
        {
            "id": "f-timeline",
            "claim": "Cross-source timeline: 92 events; 8 security logon events",
            "tags": ["R15", "timeline_correlation"],
            "status": "confirmed",
        },
        {
            "id": "f-malfind",
            "claim": "1 injected/RWX memory region(s) detected by malfind",
            "tags": ["R7"],
            "status": "confirmed",
        },
    ]
    report = score_findings(findings, gt, self_corrected=True)
    assert "AH-6" not in report.missed
    assert any(m.expected_id == "AH-6" for m in report.matched)


def test_narrative_template() -> None:
    from postmortem_agent.narrative import build_template_narrative
    from postmortem_agent.state import AgentConfig, InvestigationState

    state = InvestigationState(
        hypothesis="Host likely compromised",
        confidence=0.75,
        self_corrected=True,
    )
    state.findings = [
        {
            "id": "f-1",
            "claim": "USB KVM inserted",
            "audit_ids": ["abc12345"],
            "status": "confirmed",
            "tags": ["R12"],
        }
    ]
    state.tool_results = {"mem_pslist": [{"ok": True, "audit_id": "abc12345"}]}
    narrative = build_template_narrative(state)
    assert "MITRE" in narrative["text"]
    assert narrative["mitre"]
