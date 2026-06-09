"""Tests for Step 3 — MCP skeleton and first audited tool."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from postmortem_audit import verify_chain
from postmortem_mcp.config import audit_log_path
from postmortem_mcp.server import create_server
from postmortem_mcp.tools.memory import mem_pslist
from postmortem_mcp.vol import parse_pslist_table, run_pslist


PSLIST_FIXTURE = """\
Volatility 3 Framework 2.28.0

PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\tFile output

4\t0\tSystem\t0x82f57910\t105\t504\tN/A\tFalse\t2015-08-23 20:27:20.000000 UTC\tN/A\tDisabled
420\t4\tsmss.exe\t0x838382d0\t4\t28\tN/A\tFalse\t2015-08-23 20:27:20.000000 UTC\tN/A\tDisabled
620\t532\tlsass.exe\t0x83942020\t19\t628\t0\tFalse\t2015-08-23 20:29:18.000000 UTC\tN/A\tDisabled
"""


def test_parse_pslist_table() -> None:
    processes = parse_pslist_table(PSLIST_FIXTURE)
    assert len(processes) == 3
    assert processes[0]["pid"] == 4
    assert processes[0]["name"] == "System"
    assert processes[2]["name"] == "lsass.exe"
    assert processes[2]["wow64"] is False


def test_mem_pslist_writes_audit_and_returns_audit_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    case = evidence_root / "case-a"
    mem = case / "memdump.mem"
    mem.parent.mkdir(parents=True)
    mem.write_bytes(b"fake-memory")

    cases_root = tmp_path / "cases"
    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(cases_root))

    def fake_run_pslist(memory_path: Path, *, vol_binary: str, timeout_sec: int = 300):
        assert memory_path == mem.resolve()
        return {
            "source": str(memory_path),
            "plugin": "windows.pslist",
            "process_count": 1,
            "processes": [{"pid": 4, "name": "System"}],
        }

    monkeypatch.setattr("postmortem_mcp.tools.memory.run_pslist", fake_run_pslist)

    result = mem_pslist("demo-case", "case-a/memdump.mem", iteration=1)
    assert result["ok"] is True
    assert result["tool"] == "mem_pslist"
    assert result["audit_id"]
    assert result["data"]["process_count"] == 1

    audit_path = audit_log_path("demo-case")
    assert audit_path.exists()
    ok, message = verify_chain(audit_path)
    assert ok is True, message

    entries = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(entries) == 1
    entry = json.loads(entries[0])
    assert entry["tool"] == "mem_pslist"
    assert entry["iteration"] == 1


def test_mem_pslist_audits_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    cases_root = tmp_path / "cases"
    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(cases_root))

    result = mem_pslist("demo-case", "missing/mem.mem", iteration=0)
    assert result["ok"] is False
    assert result["audit_id"]
    assert "error" in result

    audit_path = audit_log_path("demo-case")
    ok, _ = verify_chain(audit_path)
    assert ok is True


def test_run_pslist_invokes_vol(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mem = tmp_path / "mem.mem"
    mem.write_bytes(b"x")
    calls: list[list[str]] = []

    class Proc:
        returncode = 0
        stdout = PSLIST_FIXTURE
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Proc()

    monkeypatch.setattr("postmortem_mcp.vol.subprocess.run", fake_run)
    data = run_pslist(mem, vol_binary="/usr/bin/vol")
    assert data["process_count"] == 3
    assert calls[0] == ["/usr/bin/vol", "-f", str(mem), "windows.pslist"]


def test_mcp_server_registers_mem_pslist() -> None:
    mcp = create_server()

    async def list_tools():
        return await mcp.list_tools()

    tools = asyncio.run(list_tools())
    names = {tool.name for tool in tools}
    assert "mem_pslist" in names
