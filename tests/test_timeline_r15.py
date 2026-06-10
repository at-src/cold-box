"""R15 cross-source timeline synthesis and Ali AH-6 coverage."""

from __future__ import annotations

from postmortem_agent.scoring import load_ground_truth
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.verifier_bridge import build_verify_context, run_lab_verifier
from postmortem_mcp.timeline import build_super_timeline
from postmortem_verify.rules import rule_r15_timeline_correlation


def _tool_result(tool: str, data: dict, audit_id: str = "audit-1") -> dict:
    return {"ok": True, "tool": tool, "audit_id": audit_id, "data": data}


def test_build_super_timeline_evtx_plus_memory_undated() -> None:
    timeline = build_super_timeline(
        evtx_records=[
            {"EventId": "4624", "TimeCreated": "2024-01-01 10:00:00", "TargetUserName": "admin"},
            {"EventId": "4625", "TimeCreated": "2024-01-01 10:01:00", "TargetUserName": "guest"},
        ],
        memory_processes=[{"name": "cmd.exe", "pid": 1234, "create_time": "N/A"}],
    )
    assert timeline["by_source"]["evtx"] == 2
    assert timeline["by_source"]["memory"] == 1
    assert timeline["authentication_events"] == 2


def test_r15_fires_on_synthesized_timeline() -> None:
    state = InvestigationState()
    state.tool_results = {
        "disk_evtx_filter": [
            _tool_result(
                "disk_evtx_filter",
                {
                    "records": [
                        {"EventId": "4624", "TimeCreated": "2024-01-01 10:00:00"},
                        {"EventId": "4625", "TimeCreated": "2024-01-01 10:01:00"},
                    ]
                },
                "evtx-audit",
            )
        ],
        "mem_pslist": [
            _tool_result(
                "mem_pslist",
                {"processes": [{"name": "cmd.exe", "pid": 99, "create_time": "N/A"}]},
                "pslist-audit",
            )
        ],
    }
    config = AgentConfig(case_id="t", evidence_case="ali-hadi-1")
    ctx = build_verify_context(state, config)
    assert ctx.timeline_events
    assert len({e.get("source") for e in ctx.timeline_events}) >= 2

    r15 = rule_r15_timeline_correlation(ctx)
    assert r15.status == "contradiction"
    assert "security logon" in r15.detail


def test_ali_ah6_matches_r15_finding() -> None:
    state = InvestigationState(self_corrected=True)
    state.tool_results = {
        "disk_evtx_filter": [
            _tool_result(
                "disk_evtx_filter",
                {
                    "records": [
                        {"EventId": "4624", "TimeCreated": "2024-01-01 10:00:00"},
                        {"EventId": "4625", "TimeCreated": "2024-01-01 10:01:00"},
                    ]
                },
            )
        ],
        "mem_pslist": [
            _tool_result(
                "mem_pslist",
                {"processes": [{"name": "powershell.exe", "pid": 1, "create_time": "N/A"}]},
            )
        ],
    }
    config = AgentConfig(case_id="t", evidence_case="ali-hadi-1")
    state.verifier_results = run_lab_verifier(state, config)
    r15 = next(r for r in state.verifier_results if r.rule_id == "R15")
    assert r15.status == "contradiction"
    assert "security logon" in r15.detail

    gt = load_ground_truth("ground-truth/ali-hadi-1.json")
    ah6 = next(e for e in gt["expected_findings"] if e["id"] == "AH-6")
    from postmortem_agent.scoring import _matches_expected

    finding = {
        "id": "f-r15",
        "claim": r15.detail,
        "tags": ["R15", "timeline_correlation"],
        "status": "confirmed",
    }
    assert _matches_expected(finding, ah6, self_corrected=True) == "rule tag R15"
