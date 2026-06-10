"""Phase 4 — web logs, structured logs, and network-adjacent evidence tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from postmortem_agent.core import run_investigation
from postmortem_agent.state import AgentConfig
from postmortem_mcp.catalog import CATALOG
from postmortem_mcp.dispatch import TOOL_REGISTRY
from postmortem_mcp.survey import build_survey_payload, classify_file
from postmortem_mcp.tools.logs import logs_parse_structured
from postmortem_mcp.tools.web import web_inspect_artifact, web_parse_access_log
from postmortem_verify.models import VerifyContext
from postmortem_verify.rules import rule_r19_web_attack, rule_r20_structured_log_alert

REPO = Path(__file__).resolve().parents[1]
CASE_WEB = REPO / "examples" / "case-web"


def test_catalog_drift_phase4() -> None:
    assert len(TOOL_REGISTRY) == len(CATALOG) == 56


def test_survey_web_kinds() -> None:
    payload = build_survey_payload(CASE_WEB, ".")
    kinds = set(payload["kinds_present"])
    assert "web_log" in kinds
    assert "web_artifact" in kinds
    assert "structured_log" in kinds
    access = next(f for f in payload["files"] if f["relpath"].endswith("access.log"))
    assert "web_parse_access_log" in access["applicable_tools"]
    shell = next(f for f in payload["files"] if f["relpath"].endswith("shell.php"))
    assert "web_inspect_artifact" in shell["applicable_tools"]


def test_classify_structured_log() -> None:
    path = CASE_WEB / "logs/journal.ndjson"
    assert classify_file("logs/journal.ndjson", path) == "structured_log"


def test_web_parse_access_log_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WEB))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = web_parse_access_log("t", "web/logs/access.log")
    assert result["ok"] is True
    data = result["data"]
    assert data["suspicious_count"] >= 5
    assert any("sql" in str(h.get("attack_type", "")).lower() for h in data["suspicious_requests"])


def test_web_inspect_artifact_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WEB))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = web_inspect_artifact("t", "web/var/www/html/uploads/shell.php")
    assert result["ok"] is True
    assert result["data"]["indicator_count"] >= 1


def test_logs_parse_structured_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WEB))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = logs_parse_structured("t", "logs/journal.ndjson")
    assert result["ok"] is True
    assert result["data"]["record_count"] >= 1


def test_r19_web_attack_rule() -> None:
    ctx = VerifyContext(
        web_suspicious_requests=[
            {"attack_type": "sql_injection", "request": "GET /index.php?id=1' OR '1'='1"}
        ],
        web_access_audit_id="abc12345",
    )
    result = rule_r19_web_attack(ctx)
    assert result.status == "contradiction"


def test_r20_structured_log_rule() -> None:
    ctx = VerifyContext(
        structured_log_events=[{"message": "authentication failed for user root"}],
        structured_log_audit_id="def67890",
    )
    result = rule_r20_structured_log_alert(ctx)
    assert result.status == "contradiction"


def test_autonomous_web_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WEB))
    state = run_investigation(AgentConfig(case_id="web-auto", evidence_case=".", max_iterations=20))
    assert state.done
    claims = " ".join(f.get("claim", "") for f in state.findings).lower()
    assert "web compromise" in claims or "attack request" in claims or "webshell" in claims
