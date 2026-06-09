"""Tests for Step 8 — finding gate and report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from postmortem_report.gate import FindingGateError, validate_finding, validate_findings
from postmortem_report.report import build_markdown_report, load_findings, write_report


def test_gate_rejects_empty_audit_ids() -> None:
    with pytest.raises(FindingGateError, match="audit_ids"):
        validate_finding(
            {
                "id": "f-1",
                "claim": "test",
                "audit_ids": [],
                "confidence": 0.5,
                "status": "confirmed",
            }
        )


def test_gate_rejects_missing_fields() -> None:
    with pytest.raises(FindingGateError, match="missing fields"):
        validate_finding({"id": "f-1", "claim": "x"})


def test_gate_accepts_valid_finding() -> None:
    finding = validate_finding(
        {
            "id": "f-1",
            "claim": "Hidden process detected",
            "audit_ids": ["abc12345"],
            "confidence": 0.9,
            "status": "confirmed",
        }
    )
    assert finding["audit_ids"] == ["abc12345"]


def test_report_generation(tmp_path: Path) -> None:
    case_dir = tmp_path / "report-case"
    case_dir.mkdir()
    findings = [
        {
            "id": "f-1",
            "claim": "Confirmed hidden process",
            "audit_ids": ["a1", "a2"],
            "confidence": 0.9,
            "status": "confirmed",
        },
        {
            "id": "u-1",
            "claim": "Disk artifacts not collected",
            "audit_ids": ["a1"],
            "confidence": 0.5,
            "status": "unresolved",
        },
    ]
    (case_dir / "findings.json").write_text(
        json.dumps({"findings": findings}, indent=2) + "\n",
        encoding="utf-8",
    )
    (case_dir / "progress.jsonl").write_text(
        json.dumps(
            {
                "iteration": 1,
                "ts": "2026-01-01T00:00:00.000Z",
                "phase": "finalize",
                "hypothesis": "Demo hypothesis",
                "confidence": 0.9,
                "unresolved": [],
                "notes": "done",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (case_dir / "audit.jsonl").write_text(
        json.dumps(
            {
                "audit_id": "a1",
                "ts": "t",
                "tool": "mem_pslist",
                "args": {},
                "result_digest": "sha256:x",
                "iteration": 1,
                "prev_hash": "0" * 64,
                "entry_hash": "1" * 64,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = write_report(case_dir, case_id="report-case")
    assert (case_dir / "report.md").exists()
    assert (case_dir / "report.json").exists()
    assert report["confirmed"]
    assert report["unresolved"]
    md = build_markdown_report(report)
    assert "Executive Summary" in md
    assert "Confirmed Findings" in md
    assert "Unresolved" in md
    assert "Timeline" in md


def test_agent_run_writes_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from postmortem_agent.loop import run_investigation
    from postmortem_agent.state import AgentConfig
    from postmortem_mcp.config import case_dir as output_case_dir

    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    config = AgentConfig(
        case_id="agent-report",
        evidence_case="synthetic-r1",
        mode="synthetic",
        fixture_dir=repo / "examples" / "sample-verifier",
    )
    run_investigation(config)
    out = output_case_dir(config.case_id)
    assert (out / "report.md").exists()
    assert (out / "report.json").exists()
    findings = load_findings(out / "findings.json")
    assert all(f["audit_ids"] for f in findings)
