"""Tests for Step 4 — Wave 1 MCP tool set."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from postmortem_audit import verify_chain
from postmortem_mcp.config import audit_log_path
from postmortem_mcp.ez_tools import cap_records
from postmortem_mcp.server import create_server
from postmortem_mcp.tools import ALL_TOOLS, WAVE1_TOOLS, WAVE2_TOOLS
from postmortem_mcp.tools.disk import disk_parse_prefetch
from postmortem_mcp.tools.evidence import evidence_manifest
from postmortem_mcp.tools.memory import mem_cmdline, mem_psscan
from postmortem_mcp.vol import parse_cmdline_table, parse_vol_process_table


CMDLINE_FIXTURE = """\
Volatility 3 Framework 2.28.0

PID\tProcess\tArgs

612\tcmd.exe\t"C:\\Windows\\System32\\cmd.exe"
620\tlsass.exe\tC:\\Windows\\system32\\lsass.exe
"""


def test_wave1_tool_count() -> None:
    assert len(WAVE1_TOOLS) == 8
    assert {fn.__name__ for fn in WAVE1_TOOLS} == {
        "mem_pslist",
        "mem_psscan",
        "mem_cmdline",
        "disk_parse_prefetch",
        "disk_parse_amcache",
        "disk_parse_evtx",
        "disk_parse_mft",
        "evidence_manifest",
    }


def test_wave2_tool_count() -> None:
    assert len(WAVE2_TOOLS) == 3
    assert {fn.__name__ for fn in WAVE2_TOOLS} == {
        "mem_malfind",
        "mem_netscan",
        "disk_detect_timestomp",
    }


def test_mcp_server_registers_all_tools() -> None:
    mcp = create_server()
    tools = asyncio.run(mcp.list_tools())
    names = {tool.name for tool in tools}
    assert names == {fn.__name__ for fn in ALL_TOOLS}


def test_parse_cmdline_table() -> None:
    rows = parse_cmdline_table(CMDLINE_FIXTURE)
    assert len(rows) == 2
    assert rows[0]["pid"] == 612
    assert "cmd.exe" in rows[0]["args"]


def test_cap_records_truncates() -> None:
    records = [{"i": i} for i in range(5)]
    capped = cap_records(records, 2)
    assert capped["record_count"] == 5
    assert capped["returned_count"] == 2
    assert capped["truncated"] is True
    assert len(capped["records"]) == 2


def test_evidence_manifest_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "evidence"
    case = evidence_root / "case-a"
    (case / "disk").mkdir(parents=True)
    (case / "disk" / "a.txt").write_text("hello\n", encoding="utf-8")

    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    result = evidence_manifest("manifest-case", "case-a", iteration=0)
    assert result["ok"] is True
    assert result["data"]["file_count"] == 1
    assert result["audit_id"]

    ok, _ = verify_chain(audit_log_path("manifest-case"))
    assert ok is True


def test_mem_psscan_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "evidence"
    mem = evidence_root / "case-a" / "dump.mem"
    mem.parent.mkdir(parents=True)
    mem.write_bytes(b"mem")

    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    def fake_psscan(memory_path: Path, *, vol_binary: str, timeout_sec: int = 300):
        return {
            "source": str(memory_path),
            "plugin": "windows.psscan",
            "process_count": 2,
            "processes": [{"pid": 4, "name": "System"}, {"pid": 620, "name": "lsass.exe"}],
        }

    monkeypatch.setattr("postmortem_mcp.tools.memory.run_psscan", fake_psscan)
    result = mem_psscan("psscan-case", "case-a/dump.mem")
    assert result["ok"] is True
    assert result["data"]["process_count"] == 2


def test_mem_cmdline_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "evidence"
    mem = evidence_root / "case-a" / "dump.mem"
    mem.parent.mkdir(parents=True)
    mem.write_bytes(b"mem")

    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    def fake_cmdline(memory_path: Path, *, vol_binary: str, timeout_sec: int = 300):
        rows = parse_cmdline_table(CMDLINE_FIXTURE)
        return {
            "source": str(memory_path),
            "plugin": "windows.cmdline",
            "cmdline_count": len(rows),
            "cmdlines": rows,
        }

    monkeypatch.setattr("postmortem_mcp.tools.memory.run_cmdline", fake_cmdline)
    result = mem_cmdline("cmdline-case", "case-a/dump.mem")
    assert result["ok"] is True
    assert result["data"]["cmdline_count"] == 2


def test_disk_parse_prefetch_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "evidence"
    pf = evidence_root / "case-a" / "NOTEPAD.EXE-ABC.pf"
    pf.parent.mkdir(parents=True)
    pf.write_bytes(b"pf")

    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    def fake_parse(path):
        return {
            "source": str(path),
            "executable": "NOTEPAD.EXE",
            "run_count": 3,
            "filenames": [],
        }

    monkeypatch.setattr("postmortem_mcp.tools.disk._parse_prefetch_file", fake_parse)
    result = disk_parse_prefetch("pf-case", "case-a/NOTEPAD.EXE-ABC.pf")
    assert result["ok"] is True
    assert result["data"]["prefetch"]["executable"] == "NOTEPAD.EXE"


def test_rejects_non_memory_suffix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "evidence"
    bad = evidence_root / "case-a" / "disk.E01"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"e01")

    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    from postmortem_mcp.tools.memory import mem_pslist

    result = mem_pslist("bad-case", "case-a/disk.E01")
    assert result["ok"] is False
    assert "memory image suffix" in result["error"].lower()
    assert result["audit_id"]
