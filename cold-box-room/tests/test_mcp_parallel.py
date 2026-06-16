"""Claude Code parallel track — MCP server wiring."""

from __future__ import annotations

import pytest

from cold_box_room.agent.tools import all_harness_tool_schemas
from cold_box_room.mcp.kitchen import handle_get_case_paths, handle_get_hallway_status
from cold_box_room.mcp.server import create_server, main


def test_main_importable():
    assert callable(main)


def test_create_server_registers_tools():
    server = create_server()
    assert server is not None


def test_all_harness_tool_schemas_unique():
    names = [row["name"] for row in all_harness_tool_schemas()]
    assert len(names) == len(set(names))
    assert "run_sift_tool" in names
    assert "run_skill" in names
    assert "return_to_room" in names


def test_get_case_paths(tmp_path, monkeypatch):
    staging = tmp_path / "r1"
    sandbox = tmp_path / "r2"
    records = tmp_path / "records"
    for path in (staging, sandbox, records):
        path.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(sandbox))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))

    payload = handle_get_case_paths("demo-case")
    assert payload["ok"] is True
    assert "audit_log" in payload["paths"]


def test_get_hallway_status_unknown_case(tmp_path, monkeypatch):
    staging = tmp_path / "r1"
    records = tmp_path / "records"
    staging.mkdir()
    records.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(tmp_path / "r2"))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))

    payload = handle_get_hallway_status("missing-case")
    assert payload["ok"] is False
