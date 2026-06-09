"""Catalog and survey tests for autonomous agent."""

from __future__ import annotations

from pathlib import Path

import pytest

from postmortem_mcp.catalog import CATALOG
from postmortem_mcp.dispatch import TOOL_REGISTRY
from postmortem_mcp.survey import build_survey_payload, classify_file


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_catalog_drift() -> None:
    registry = set(TOOL_REGISTRY.keys())
    catalog = set(CATALOG.keys())
    assert registry == catalog, f"missing in catalog: {registry - catalog}, extra: {catalog - registry}"


def test_survey_sample_evidence() -> None:
    root = REPO_ROOT / "examples" / "sample-evidence"
    payload = build_survey_payload(root, ".")
    kinds = set(payload["kinds_present"])
    assert "prefetch" in kinds or "mft" in kinds
    assert payload["files"]
    for entry in payload["files"]:
        assert entry["kind"]
        assert isinstance(entry["applicable_tools"], list)


def test_classify_prefetch() -> None:
    path = REPO_ROOT / "examples/sample-evidence/disk/Windows/Prefetch/COLDLOADER.EXE-B1C2D3E4.pf"
    assert classify_file(path.name, path) == "prefetch"


def test_no_hardcoded_path_in_agent_modules() -> None:
    agent_dir = REPO_ROOT / "postmortem_agent"
    banned = ("steps = [", "R1_PLAN", "LAB_DISK_STEPS", "build_ali_hadi_findings")
    for path in agent_dir.glob("*.py"):
        if path.name in {"ali_hadi.py", "tools.py"}:
            continue
        text = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{path.name} contains banned pattern {token!r}"
