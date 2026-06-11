"""Optional GT finding builders (Ali Hadi, NDLC antiforensic peak)."""

from __future__ import annotations

from postmortem_agent.findings import build_findings
from postmortem_agent.scoring import load_ground_truth, score_findings
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_verify.models import RuleResult


def test_peak_r5_surfaces_antiforensic_gt() -> None:
    state = InvestigationState(hypothesis="Insider exfil triage")
    state.peak_contradictions["R5"] = RuleResult(
        "R5",
        "ghost_binary",
        "contradiction",
        "3 prefetch executable(s) missing on disk (CLEANUP.EXE)",
        [{"audit_id": "pf-1"}],
    )
    state.verifier_results = [
        RuleResult("R5", "ghost_binary", "pass", "All prefetch executable(s) exist in evidence", [])
    ]
    state.tool_results["disk_parse_prefetch"] = [{"ok": True, "audit_id": "pf-1", "data": {}}]
    findings = build_findings(state, partial=False)
    gt = load_ground_truth("ground-truth/nist-ndlc.json")
    report = score_findings(findings, gt, self_corrected=True)
    assert "F-ANTIFORENSIC" in {m.expected_id for m in report.matched}


def test_ali_hadi_optional_logon_and_software() -> None:
    state = InvestigationState(
        hypothesis="Web server breach",
        survey={"kinds_present": ["memory_image", "evtx"], "files": []},
    )
    state.verifier_results = [
        RuleResult("R7", "memory_injection", "contradiction", "injected region", [])
    ]
    state.tool_results["disk_evtx_filter"] = [
        {
            "ok": True,
            "audit_id": "evtx-1",
            "data": {"event_id_counts": {"4624": 12, "4625": 4}},
        }
    ]
    state.tool_results["mem_cmdline"] = [
        {
            "ok": True,
            "audit_id": "cmd-1",
            "data": {
                "cmdlines": [
                    {"process": "xampp-control.exe", "args": "C:\\xampp\\xampp-control.exe"},
                ]
            },
        }
    ]
    config = AgentConfig(case_id="ali-hadi-1", evidence_case="ali-hadi-1")
    findings = build_findings(state, partial=False, config=config)
    tags = {tag for f in findings for tag in f.get("tags", [])}
    assert "AH-2" in tags
    assert "AH-4" in tags


def test_ali_hadi7_hosts_modification_inference() -> None:
    state = InvestigationState(hypothesis="Fake SysInternals installer")
    state.verifier_results = [
        RuleResult(
            "R16",
            "unusual_execution",
            "contradiction",
            "Suspicious SysInternals-like installer",
            [{"audit_id": "r16-1"}],
        )
    ]
    state.tool_results["disk_parse_prefetch"] = [{"ok": True, "audit_id": "r16-1", "data": {}}]
    config = AgentConfig(case_id="ali-hadi-7", evidence_case="ali-hadi-7")
    findings = build_findings(state, partial=False, config=config)
    hosts = [f for f in findings if "F-HOSTS-MODIFICATION" in f.get("tags", [])]
    assert hosts
    assert "hosts file" in hosts[0]["claim"].lower()
