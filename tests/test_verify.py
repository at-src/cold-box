"""Tests for Step 5 — verifier R1 hidden_process."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from postmortem_verify import VerifyContext, run_r1, run_verifier
from postmortem_verify.rules import rule_r1_hidden_process

REPO_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_PSLIST = REPO_ROOT / "examples" / "sample-verifier" / "r1-pslist.json"
SYNTHETIC_PSSCAN = REPO_ROOT / "examples" / "sample-verifier" / "r1-psscan.json"


def _process(pid: int, name: str, offset: str) -> dict:
    return {
        "pid": pid,
        "ppid": 0,
        "name": name,
        "offset": offset,
        "threads": 1,
        "handles": 1,
        "session_id": "0",
        "wow64": False,
        "create_time": "t",
        "exit_time": "N/A",
        "file_output": "Disabled",
    }


def test_r1_pass_when_pslist_matches_psscan() -> None:
    processes = [_process(4, "System", "0x1"), _process(620, "lsass.exe", "0x2")]
    ctx = VerifyContext(pslist_processes=processes, psscan_processes=processes)
    result = rule_r1_hidden_process(ctx)
    assert result.rule_id == "R1"
    assert result.rule_name == "hidden_process"
    assert result.status == "pass"


def test_r1_contradiction_when_pid_missing_from_pslist() -> None:
    pslist = [_process(4, "System", "0x1")]
    psscan = pslist + [_process(31337, "evil.exe", "0xdeadbeef")]
    ctx = VerifyContext(
        pslist_processes=pslist,
        psscan_processes=psscan,
        pslist_audit_id="aaa11111",
        psscan_audit_id="bbb22222",
    )
    result = rule_r1_hidden_process(ctx)
    assert result.status == "contradiction"
    assert "31337" in result.detail or "1 suspicious" in result.detail
    assert any(src.get("pid") == 31337 for src in result.sources)
    assert any(src.get("audit_id") == "aaa11111" for src in result.sources)


def test_r1_contradiction_on_name_mismatch() -> None:
    pslist = [_process(612, "cmd.exe", "0x111")]
    psscan = [_process(612, "injected.exe", "0x222")]
    result = rule_r1_hidden_process(
        VerifyContext(pslist_processes=pslist, psscan_processes=psscan)
    )
    assert result.status == "contradiction"
    assert "name mismatch" in result.detail


def test_r1_skipped_without_inputs() -> None:
    result = rule_r1_hidden_process(VerifyContext())
    assert result.status == "skipped"


def test_synthetic_fixture_fires_r1() -> None:
    pslist = json.loads(SYNTHETIC_PSLIST.read_text(encoding="utf-8"))
    psscan = json.loads(SYNTHETIC_PSSCAN.read_text(encoding="utf-8"))
    ctx = VerifyContext.from_tool_payloads(pslist_data=pslist, psscan_data=psscan)
    result = run_r1(ctx)
    assert result.status == "contradiction"
    assert any(src.get("name") == "evil.exe" for src in result.sources)


def test_run_verifier_returns_all_rules() -> None:
    processes = [_process(4, "System", "0x1")]
    ctx = VerifyContext(pslist_processes=processes, psscan_processes=processes)
    results = run_verifier(ctx)
    assert len(results) == 19
    assert [result.rule_id for result in results] == [
        "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10",
        "R11", "R12", "R13", "R14", "R15", "R16", "R18", "R19", "R20",
    ]


def test_r2_contradiction_without_execution_trail() -> None:
    pslist = json.loads((REPO_ROOT / "examples/sample-verifier/r2-pslist.json").read_text())
    amcache = json.loads((REPO_ROOT / "examples/sample-verifier/r2-amcache.json").read_text())
    prefetch = json.loads((REPO_ROOT / "examples/sample-verifier/r2-prefetch.json").read_text())
    ctx = VerifyContext.from_tool_payloads(
        pslist_data=pslist,
        psscan_data=pslist,
        amcache_data=amcache,
        prefetch_data=prefetch,
    )
    from postmortem_verify.rules import rule_r2_no_execution_trail

    result = rule_r2_no_execution_trail(ctx)
    assert result.status == "contradiction"
    assert "ghostrunner.exe" in result.detail


def test_r3_phantom_logon_fixture() -> None:
    pslist = json.loads((REPO_ROOT / "examples/sample-verifier/r3-pslist.json").read_text())
    security = json.loads((REPO_ROOT / "examples/sample-verifier/r3-security.json").read_text())
    ctx = VerifyContext.from_tool_payloads(pslist_data=pslist, security_data=security)
    from postmortem_verify.rules import rule_r3_phantom_logon

    result = rule_r3_phantom_logon(ctx)
    assert result.status == "contradiction"
    assert "phantom.admin" in result.detail


def test_r7_memory_injection() -> None:
    from postmortem_verify.rules import rule_r7_memory_injection

    ctx = VerifyContext.from_tool_payloads(malfind_data={"finding_count": 2, "findings": [{}, {}]})
    result = rule_r7_memory_injection(ctx)
    assert result.status == "contradiction"
    assert "2" in result.detail


def test_r4_contradiction_on_timestomp_fixture() -> None:
    mft = json.loads((REPO_ROOT / "examples/sample-verifier/r4-mft.json").read_text())
    ctx = VerifyContext.from_tool_payloads(mft_data=mft)
    from postmortem_verify.rules import rule_r4_timestomp

    result = rule_r4_timestomp(ctx)
    assert result.status == "contradiction"


def test_r5_contradiction_on_missing_binary() -> None:
    prefetch = json.loads((REPO_ROOT / "examples/sample-verifier/r5-prefetch.json").read_text())
    ctx = VerifyContext.from_tool_payloads(
        pslist_data={"processes": []},
        psscan_data={"processes": []},
        prefetch_data=prefetch,
        evidence_root=REPO_ROOT / "examples" / "sample-evidence",
    )
    from postmortem_verify.rules import rule_r5_ghost_binary

    result = rule_r5_ghost_binary(ctx)
    assert result.status == "contradiction"
    assert "STAGE-RUNNER.EXE" in result.detail


def test_r6_contradiction_on_orphan_connection() -> None:
    pslist = json.loads((REPO_ROOT / "examples/sample-verifier/r6-pslist.json").read_text())
    netscan = json.loads((REPO_ROOT / "examples/sample-verifier/r6-netscan.json").read_text())
    ctx = VerifyContext.from_tool_payloads(pslist_data=pslist, netscan_data=netscan)
    from postmortem_verify.rules import rule_r6_orphan_connection

    result = rule_r6_orphan_connection(ctx)
    assert result.status == "contradiction"
    assert "31337" in result.detail


def test_cli_r1_on_synthetic_fixture() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "postmortem_verify.cli",
            "r1",
            "--pslist",
            str(SYNTHETIC_PSLIST),
            "--psscan",
            str(SYNTHETIC_PSSCAN),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["status"] == "contradiction"
    assert payload["rule_name"] == "hidden_process"
