"""Phase 2 — Windows depth, registry, memory depth, timeline_super."""

from __future__ import annotations

from pathlib import Path

import pytest

from postmortem_agent.core import run_investigation
from postmortem_agent.state import AgentConfig
from postmortem_mcp.catalog import CATALOG
from postmortem_mcp.dispatch import TOOL_REGISTRY
from postmortem_mcp.survey import build_survey_payload, classify_file
from postmortem_mcp.tools.analysis import timeline_super
from postmortem_mcp.tools.disk import disk_parse_scheduled_tasks, disk_parse_setupapi
from postmortem_mcp.tools.registry import reg_services
from postmortem_verify.models import VerifyContext, evidence_basenames
from postmortem_verify.rules import (
    rule_r11_ghost_service,
    rule_r12_usb_initial_access,
    rule_r13_scheduled_task,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CASE_WINDOWS = REPO_ROOT / "examples" / "case-windows"


def test_catalog_drift_phase2() -> None:
    assert len(TOOL_REGISTRY) == len(CATALOG) == 59


def test_survey_windows_kinds() -> None:
    payload = build_survey_payload(CASE_WINDOWS, ".")
    kinds = set(payload["kinds_present"])
    assert "setupapi_log" in kinds
    assert "scheduled_task" in kinds
    assert "shimcache" in kinds
    assert "services_csv" in kinds

    setup_path = CASE_WINDOWS / "disk/Windows/INF/setupapi.dev.log"
    assert classify_file("disk/Windows/INF/setupapi.dev.log", setup_path) == "setupapi_log"


def test_disk_parse_setupapi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WINDOWS))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = disk_parse_setupapi("t", "disk/Windows/INF/setupapi.dev.log")
    assert result["ok"] is True
    data = result["data"]
    assert data["suspicious_count"] >= 1
    assert any(d.get("vid") == "0557" for d in data["records"])


def test_disk_parse_scheduled_tasks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WINDOWS))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = disk_parse_scheduled_tasks("t", "disk/Windows/System32/Tasks/RemoteHandsSync")
    assert result["ok"] is True
    assert result["data"]["suspicious"] is True
    assert "remote-admin" in result["data"]["command"].lower()


def test_reg_services_ghost(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WINDOWS))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = reg_services("t", "disk/Windows/System32/config/SYSTEM.services.csv")
    assert result["ok"] is True
    basenames = {row["binary_basename"] for row in result["data"]["records"]}
    assert "ghost-service.exe" in basenames


def test_reg_services_system_hive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hive = Path("/tmp/cb-cases/ali-hadi-7/extracted/part0/Windows/System32/config/SYSTEM")
    if not hive.is_file():
        pytest.skip("ali-hadi-7 SYSTEM hive not available")
    monkeypatch.setenv("EVIDENCE_ROOT", "/tmp/cb-cases/ali-hadi-7")
    monkeypatch.setenv("EXTRACTED_ROOT", "/tmp/cb-cases/ali-hadi-7/extracted")
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = reg_services("t", "extracted/part0/Windows/System32/config/SYSTEM")
    assert result["ok"] is True
    assert result["data"]["parser"] == "regipy-services"
    basenames = {row["binary_basename"] for row in result["data"]["records"]}
    assert "vmtoolsio.exe" in basenames


def test_r11_skips_known_good_service_binaries() -> None:
    ctx = VerifyContext(
        service_entries=[
            {
                "name": "Spooler",
                "binary": r"C:\Windows\System32\spoolsv.exe",
                "binary_basename": "spoolsv.exe",
            }
        ],
        evidence_basenames=evidence_basenames(CASE_WINDOWS),
        services_audit_id="aaaabbbb",
    )
    result = rule_r11_ghost_service(ctx)
    assert result.status == "pass"


def test_r12_usb_rule() -> None:
    ctx = VerifyContext(
        setupapi_devices=[
            {
                "vid": "0557",
                "pid": "2419",
                "device_id": "USB\\VID_0557&PID_2419",
                "timestamp": "2026/03/15 14:19:47.018",
                "suspicious_kvm": True,
            }
        ],
        setupapi_audit_id="abcd1234",
    )
    result = rule_r12_usb_initial_access(ctx)
    assert result.status == "contradiction"
    assert "0557" in result.detail or "IP-KVM" in result.detail


def test_r13_scheduled_task_rule() -> None:
    ctx = VerifyContext(
        scheduled_tasks=[
            {
                "task_name": "RemoteHandsSync",
                "command": r"C:\Users\analyst\Downloads\remote-admin.exe",
                "suspicious": True,
            }
        ],
        scheduled_task_audit_id="efgh5678",
    )
    result = rule_r13_scheduled_task(ctx)
    assert result.status == "contradiction"


def test_r11_ghost_service_rule() -> None:
    root = CASE_WINDOWS
    ctx = VerifyContext(
        service_entries=[
            {
                "name": "RemoteHandsSvc",
                "binary": r"C:\Users\analyst\Downloads\ghost-service.exe",
                "binary_basename": "ghost-service.exe",
            }
        ],
        evidence_basenames=evidence_basenames(root),
        services_audit_id="aaaabbbb",
    )
    result = rule_r11_ghost_service(ctx)
    assert result.status == "contradiction"


def test_timeline_super(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WINDOWS))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    result = timeline_super(
        "t",
        setupapi_relpath="disk/Windows/INF/setupapi.dev.log",
        scheduled_task_relpath="disk/Windows/System32/Tasks/RemoteHandsSync",
        shimcache_relpath="disk/Windows/System32/config/SYSTEM.shimcache.csv",
    )
    assert result["ok"] is True
    data = result["data"]
    assert "setupapi" in data["sources"]
    assert data["event_count"] >= 2


def test_autonomous_windows_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))
    monkeypatch.setenv("EVIDENCE_ROOT", str(CASE_WINDOWS))
    state = run_investigation(
        AgentConfig(case_id="win-auto", evidence_case=".", max_iterations=25)
    )
    fired = {r.rule_id for r in state.verifier_results if r.status == "contradiction"}
    assert "R12" in fired or "R13" in fired or "R11" in fired
    assert state.findings
