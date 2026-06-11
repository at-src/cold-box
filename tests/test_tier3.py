"""Tier-3 breadth — exfil scan, YARA, Linux memory ISF probe, verifier R27–R31."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from postmortem_mcp.exfil_parse import scan_exfil_channels
from postmortem_mcp.yara_scan import scan_with_yara
from postmortem_mcp.vol import probe_linux_memory
from postmortem_verify import VerifyContext
from postmortem_verify.rules import (
    rule_r27_email_exfil,
    rule_r28_cloud_exfil,
    rule_r29_optical_exfil,
    rule_r30_yara_malware,
    rule_r31_linux_memory_isf,
)


def test_scan_exfil_channels_finds_email_and_cloud(tmp_path: Path) -> None:
    (tmp_path / "browser.txt").write_text(
        "User opened gmail and uploaded files to dropbox sync client\n",
        encoding="utf-8",
    )
    payload = scan_exfil_channels(tmp_path, max_hits=10)
    channels = {hit["channel"] for hit in payload["hits"]}
    assert "email" in channels
    assert "cloud" in channels


def test_yara_pattern_fallback_finds_eicar(tmp_path: Path) -> None:
    (tmp_path / "test.txt").write_bytes(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
    payload = scan_with_yara(tmp_path, max_matches=5)
    assert payload["match_count"] >= 1
    assert payload["matches"][0]["rule"] == "EICAR-Test-File"


def test_r27_email_exfil_contradiction() -> None:
    ctx = VerifyContext(
        exfil_hits=[{"channel": "email", "pattern": "gmail", "relpath": "a.txt", "snippet": "gmail"}],
        exfil_audit_id="aud-exfil",
    )
    result = rule_r27_email_exfil(ctx)
    assert result.status == "contradiction"
    assert "email" in result.detail.lower()


def test_r30_yara_malware_contradiction() -> None:
    ctx = VerifyContext(
        yara_matches=[{"rule": "EICAR-Test-File", "path": "/tmp/x", "engine": "pattern-fallback"}],
        yara_audit_id="aud-yara",
    )
    result = rule_r30_yara_malware(ctx)
    assert result.status == "contradiction"
    assert "EICAR" in result.detail


def test_r31_linux_memory_isf_gap_pass() -> None:
    ctx = VerifyContext(
        linux_memory_probe={
            "parser": "linux-memory-probe",
            "isf_gap": True,
            "isf_detail": "No symbol table found for Linux",
            "platform": "linux",
        },
        linux_memory_audit_id="aud-linux",
    )
    result = rule_r31_linux_memory_isf(ctx)
    assert result.status == "pass"
    assert "isf" in result.detail.lower()


def test_probe_linux_memory_isf_gap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mem = tmp_path / "challenge.mem"
    mem.write_bytes(b"\x00" * 16)

    def fake_run(cmd, **kwargs):
        proc = MagicMock()
        proc.returncode = 1
        proc.stdout = ""
        proc.stderr = "Unable to find suitable ISF for Linux memory"
        return proc

    monkeypatch.setattr("postmortem_mcp.vol.subprocess.run", fake_run)
    payload = probe_linux_memory(mem, vol_binary="vol")
    assert payload["isf_gap"] is True
