"""Regression tests for Tier-3 coverage + factual finding status."""

from __future__ import annotations

from postmortem_agent.findings import FACT_CONFIRMED_RULES, build_findings, _hacktool_prefetch_finding
from postmortem_agent.reasoner_policy import _coverage_tool_args
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_verify.models import RuleResult


def test_coverage_tool_args_exfil_and_yara() -> None:
    config = AgentConfig(case_id="nist-ndlc", evidence_case="nist-pc-only")
    config.extracted_root = __import__("pathlib").Path("/tmp/cb-cases/nist-ndlc/extracted")
    survey = {"files": [{"relpath": "nist-pc-only", "kind": "case_directory"}]}
    exfil = _coverage_tool_args("disk_scan_exfil", survey, config)
    yara = _coverage_tool_args("yara_scan_evidence", survey, config)
    assert exfil == {"search_root_relpath": "extracted", "max_hits": 40}
    assert yara == {"search_root_relpath": "extracted", "max_matches": 30}


def test_r21_usb_is_confirmed_without_compromise() -> None:
    state = InvestigationState(
        verifier_results=[
            RuleResult(
                "R21",
                "removable_storage",
                "contradiction",
                "2 removable USB mass-storage device(s)",
                [{"type": "audit", "audit_id": "a1"}],
            )
        ],
        tool_results={"disk_parse_usb": [{"ok": True, "audit_id": "a1", "data": {}}]},
    )
    findings = build_findings(state, partial=False)
    usb = next(f for f in findings if "R21" in f.get("tags", []))
    assert usb["status"] == "confirmed"
    assert "R21" in FACT_CONFIRMED_RULES


def test_hacktool_prefetch_finding() -> None:
    state = InvestigationState(
        tool_results={
            "disk_parse_prefetch": [
                {
                    "ok": True,
                    "audit_id": "pf1",
                    "data": {"executable": "NETSTUMBLER.EXE-0BFEE568.pf"},
                },
                {
                    "ok": True,
                    "audit_id": "pf2",
                    "data": {"executable": "123WASP_SETUP.EXE-333BB1F4.pf"},
                },
            ]
        }
    )
    finding = _hacktool_prefetch_finding(state, 1)
    assert finding is not None
    assert finding["status"] == "confirmed"
    assert "netstumbler" in finding["claim"].lower()
