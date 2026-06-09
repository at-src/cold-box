"""Adversarial bypass tests — architectural guardrails must hold."""

from __future__ import annotations

import pytest

from postmortem_evidence.guard import EvidencePathError, resolve_read_path
from postmortem_mcp.dispatch import FORBIDDEN_TOOLS, ToolNotFound, call_tool, list_tools


def test_unregistered_destructive_function_raises_tool_not_found() -> None:
    for forbidden in FORBIDDEN_TOOLS:
        with pytest.raises(ToolNotFound, match="ToolNotFound"):
            call_tool(forbidden, {})


def test_unknown_tool_raises_tool_not_found() -> None:
    with pytest.raises(ToolNotFound, match="ToolNotFound"):
        call_tool("totally_fake_tool_xyz", {})


def test_surface_includes_wave2_tools() -> None:
    names = set(list_tools())
    assert "mem_netscan" in names
    assert "mem_malfind" in names
    assert "disk_detect_timestomp" in names
    assert "execute_shell" not in names


def test_relative_path_traversal_is_blocked(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    case = evidence_root / "case-a"
    mem = case / "memdump.mem"
    mem.parent.mkdir(parents=True)
    mem.write_bytes(b"fake")
    monkeypatch.setenv("EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("CASE_OUTPUT", str(tmp_path / "cases"))

    with pytest.raises(EvidencePathError):
        resolve_read_path("../../../etc/passwd")


def test_forbidden_tools_not_in_registry() -> None:
    registered = set(list_tools())
    assert registered.isdisjoint(FORBIDDEN_TOOLS)
