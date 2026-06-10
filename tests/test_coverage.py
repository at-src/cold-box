"""Coverage frontier and sidecar synthesis tests."""

from __future__ import annotations

from pathlib import Path

from postmortem_agent.coverage import build_frontier, coverage_report, should_block_done
from postmortem_agent.state import AgentConfig
from postmortem_mcp.artifact_parse import load_amcache_with_fallbacks
from postmortem_mcp.survey import build_survey_payload, classify_file
from postmortem_verify import VerifyContext, run_verifier
from postmortem_verify.rules import rule_r16_unusual_execution


REPO = Path(__file__).resolve().parents[1]
DART = Path("/opt/ref/agentic-dart/examples/sample-evidence")


def test_classify_web_artifacts() -> None:
    php = DART / "web/var/www/html/uploads/shell.php"
    assert classify_file("web/var/www/html/uploads/shell.php", php) == "web_artifact"
    log = DART / "web/logs/access.log"
    assert classify_file("web/logs/access.log", log) == "web_log"


def test_amcache_synthesis_from_dart_sidecars() -> None:
    hive = DART / "disk/Windows/AppCompat/Programs/Amcache.hve"
    payload = load_amcache_with_fallbacks(hive, case_root=DART, max_records=50)
    records = payload.get("records") or []
    assert records
    names = {str(r.get("FileName") or r.get("FullPath") or "").lower() for r in records}
    assert any("remote-admin" in name for name in names)


def test_r16_fires_on_synthesized_execution() -> None:
    hive = DART / "disk/Windows/AppCompat/Programs/Amcache.hve"
    payload = load_amcache_with_fallbacks(hive, case_root=DART, max_records=50)
    ctx = VerifyContext.from_tool_payloads(
        amcache_data=payload,
        amcache_audit_id="abc12345",
    )
    result = rule_r16_unusual_execution(ctx)
    assert result.status == "contradiction"
    assert "remote-admin" in result.detail.lower()


def test_coverage_requires_disk_search_for_web_surface() -> None:
    if not DART.is_dir():
        return
    survey = build_survey_payload(DART, ".")
    config = AgentConfig(case_id="t", evidence_case=".")
    report = coverage_report(survey, config, executed=set(), failed=set())
    tools = {item.tool for item in report.pending}
    assert "disk_search_artifacts" in tools
    assert should_block_done(report)


def test_frontier_blocks_done_until_search_runs() -> None:
    config = AgentConfig(case_id="t", evidence_case=".")
    survey = {
        "kinds_present": ["web_artifact"],
        "files": [
            {
                "relpath": "web/uploads/shell.php",
                "kind": "web_artifact",
                "applicable_tools": ["disk_search_artifacts"],
            }
        ],
    }
    executed = {
        'mem_pslist:{"memory_relpath": "mem.raw"}',
    }
    report = coverage_report(survey, config, executed=executed, failed=set())
    assert should_block_done(report)
    assert any(item.tool == "disk_search_artifacts" for item in report.pending)
