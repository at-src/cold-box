"""Tests for Step 6 — autonomous agent loop and self-correction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from postmortem_agent.core import run_investigation
from postmortem_agent.state import AgentConfig
from postmortem_audit import verify_chain
from postmortem_mcp.config import audit_log_path, case_dir


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "examples" / "sample-verifier"


def test_synthetic_run_self_correction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    config = AgentConfig(
        case_id="agent-synthetic",
        evidence_case="synthetic-r1",
        mode="synthetic",
        max_iterations=15,
        fixture_dir=FIXTURE_DIR,
    )
    state = run_investigation(config)

    assert state.done is True
    assert state.self_corrected is True
    assert state.phase == "finalize"
    assert "mem_pslist" in state.tool_results
    assert "mem_psscan" in state.tool_results

    out = case_dir(config.case_id)
    progress_lines = (out / "progress.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(progress_lines) >= 4
    notes_blob = "\n".join(progress_lines)
    assert "self-correction" in notes_blob

    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert findings["findings"]
    assert findings["findings"][0]["audit_ids"]

    ok, _ = verify_chain(audit_log_path(config.case_id))
    assert ok is True


def test_progress_fields_each_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    config = AgentConfig(
        case_id="progress-fields",
        evidence_case="synthetic-r1",
        mode="synthetic",
        fixture_dir=FIXTURE_DIR,
        max_iterations=12,
    )
    run_investigation(config)
    for line in (case_dir(config.case_id) / "progress.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        for key in ("iteration", "ts", "phase", "hypothesis", "confidence", "unresolved", "notes"):
            assert key in entry


def test_max_iterations_partial_closeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    config = AgentConfig(
        case_id="max-iter",
        evidence_case="synthetic-r1",
        mode="synthetic",
        max_iterations=1,
        fixture_dir=FIXTURE_DIR,
    )
    state = run_investigation(config)
    assert state.done is True
    assert state.iteration <= 1 or "partial" in state.last_notes


def test_sample_evidence_autonomous_survey(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    monkeypatch.setenv("EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "sample-evidence"))
    config = AgentConfig(
        case_id="agent-sample",
        evidence_case=".",
        mode="autonomous",
        max_iterations=8,
        fixture_dir=FIXTURE_DIR,
        use_fixtures=True,
    )
    state = run_investigation(config)
    assert state.done is True
    assert state.survey.get("kinds_present")
    assert "prefetch" in state.survey.get("kinds_present", []) or "mft" in state.survey.get("kinds_present", [])


def test_cli_synthetic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    import sys

    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "postmortem_agent.cli",
            "run",
            "--case-id",
            "cli-synthetic",
            "--evidence-case",
            "synthetic-r1",
            "--synthetic",
            "--fixture-dir",
            str(FIXTURE_DIR),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["self_corrected"] is True
