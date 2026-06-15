"""Regression tests for skill harness fixes (shellbag, snort, MFT guard)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "skills" / "library"


def _load_agent(slug: str):
    script = LIB / slug / "scripts" / "agent.py"
    spec = importlib.util.spec_from_file_location(f"agent_{slug}", script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_shellbag_defines_has_regipy_when_registry_missing():
    mod = _load_agent("cb-windows-shellbag-artifacts")
    assert hasattr(mod, "HAS_REGIPY")
    assert isinstance(mod.HAS_REGIPY, bool)


def test_snort_module_loads_without_daq_dir_name_error():
    mod = _load_agent("cb-configuring-snort-ids-for-intrusion-detection")
    assert mod.DAQ_DIR


def test_rekall_module_loads_without_rekall_installed():
    mod = _load_agent("cb-extracting-memory-artifacts-with-rekall")
    assert hasattr(mod, "HAS_REKALL")
    assert mod.HAS_REKALL is False


def test_crowdstrike_module_loads_without_falconpy_exit():
    mod = _load_agent("cb-deploying-edr-agent-with-crowdstrike")
    assert hasattr(mod, "HAS_FALCONPY")


def test_detect_filesystem_reads_mmls(monkeypatch):
    from cold_box_room.skills import script_helpers

    monkeypatch.setattr(
        script_helpers,
        "run_cmd",
        lambda cmd: ("63      63      0000000000002048  0000000000000000  0000000000000000  0000000000000000  0000000000000000  FAT32 (0x0C)\n", "", 0),
    )
    assert script_helpers.detect_filesystem("/fake.E01") == "FAT32"
