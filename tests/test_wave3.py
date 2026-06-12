"""Tests for Wave 3 MCP tools and timeline correlation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from postmortem_mcp.server import create_server
from postmortem_mcp.timeline import build_correlated_timeline, search_evidence_tree
from postmortem_mcp.tools import ALL_TOOLS, WAVE3_TOOLS
from postmortem_mcp.tools.analysis import disk_correlate_timeline, disk_search_artifacts
from postmortem_mcp.vol import parse_pstree_table


PSTREE_FIXTURE = """\
Volatility 3 Framework 2.28.0

PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\tAudit\tCmd\tPath

4\t0\tSystem\t0x82f57910\t105\t504\tN/A\tFalse\t2015-08-23 20:27:20.000000 UTC\tN/A\t-\t-\t-
* 420\t4\tsmss.exe\t0x838382d0\t4\t28\tN/A\tFalse\t2015-08-23 20:27:20.000000 UTC\tN/A\t-\t-\t-
** 608\t532\tservices.exe\t0x8393bd90\t7\t238\t0\tFalse\t2015-08-23 20:29:06.000000 UTC\tN/A\t-\t-\t-
"""


def test_wave3_tool_count() -> None:
    assert len(WAVE3_TOOLS) == 7
    assert len(ALL_TOOLS) == 69
    assert {fn.__name__ for fn in WAVE3_TOOLS} == {
        "mem_pstree",
        "mem_dlllist",
        "mem_svcscan",
        "disk_evtx_filter",
        "disk_parse_registry",
        "disk_correlate_timeline",
        "disk_search_artifacts",
    }


def test_mcp_server_registers_wave3() -> None:
    mcp = create_server()
    tools = asyncio.run(mcp.list_tools())
    names = {tool.name for tool in tools}
    assert len(names) == 69
    assert "disk_correlate_timeline" in names


def test_parse_pstree_table() -> None:
    rows = parse_pstree_table(PSTREE_FIXTURE)
    assert len(rows) == 3
    assert rows[1]["depth"] == 1
    assert rows[1]["name"] == "smss.exe"
    assert rows[2]["depth"] == 2


def test_build_correlated_timeline() -> None:
    timeline = build_correlated_timeline(
        evtx_records=[
            {"EventId": "4624", "TimeCreated": "2020-01-01 10:00:00", "TargetUserName": "admin"},
            {"EventId": "4625", "TimeCreated": "2020-01-01 10:01:00"},
        ],
        mft_records=[{"FileName": "evil.exe", "Created0x10": "2020-01-01 09:59:00"}],
        memory_processes=[{"name": "cmd.exe", "pid": 612, "create_time": "2020-01-01 10:02:00 UTC"}],
    )
    assert timeline["event_count"] == 4
    assert set(timeline["by_source"].keys()) == {"evtx", "mft", "memory"}
    assert timeline["authentication_events"] == 2


def test_search_evidence_tree(tmp_path: Path) -> None:
    root = tmp_path / "case"
    (root / "web").mkdir(parents=True)
    (root / "web" / "shell.php").write_text("<?php system($_GET['cmd']); ?>", encoding="utf-8")
    hits = search_evidence_tree(root, ["system(", "shell.php"])
    assert hits["hit_count"] >= 1
    assert hits["hits"][0]["path"].endswith("shell.php")


def test_disk_search_artifacts_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "evidence"
    case = evidence_root / "case-a"
    (case / "uploads").mkdir(parents=True)
    (case / "uploads" / "x.php").write_text("eval($_POST['x']);", encoding="utf-8")

    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    result = disk_search_artifacts("search-case", "case-a", ["eval(", "php"])
    assert result["ok"] is True
    assert result["data"]["hit_count"] >= 1


def test_disk_correlate_timeline_mft_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "evidence"
    mft = evidence_root / "case-a" / "disk" / "$MFT.csv"
    mft.parent.mkdir(parents=True)
    mft.write_text(
        "FileName,Created0x10\nC:\\evil.exe,2020-01-01 10:00:00\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    result = disk_correlate_timeline(
        "timeline-case",
        mft_relpath="case-a/disk/$MFT.csv",
    )
    assert result["ok"] is True
    assert result["data"]["event_count"] >= 1
    assert "mft" in result["data"]["sources"]
