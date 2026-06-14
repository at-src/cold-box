"""MCP handlers — list, describe, room gate, run, analyze."""

from pathlib import Path

import pytest

from cold_box_room.mcp.handlers import (
    handle_analyze_scratch,
    handle_describe_sift_tool,
    handle_list_sift_tools,
    handle_run_sift_tool,
)
from cold_box_room.testing import bootstrap_case_to_room2
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import case_records_dir, case_staging_dir
from cold_box_room.r2.output_files import scratch_dir
from cold_box_room.tools.registry import clear_registry_cache


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    sandbox = tmp_path / "r2-sandbox"
    records = tmp_path / "records"
    for path in (staging, sandbox, records):
        path.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(sandbox))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))
    clear_registry_cache()
    yield
    clear_registry_cache()


def test_list_sift_tools_returns_catalog_rows():
    result = handle_list_sift_tools(runnable_only=False)
    assert result["count"] == 234
    assert result["tools"][0]["tool_id"] == "SIFT-001"
    assert "categories" in result


def test_describe_sift_tool_fls():
    result = handle_describe_sift_tool("SIFT-148")
    assert result["name"] == "fls"
    assert result["verification"]["label"] == "lab tested"
    assert result["input"]["harness_usage"]


def test_describe_unknown_tool():
    result = handle_describe_sift_tool("SIFT-999")
    assert result["ok"] is False


def test_run_sift_tool_requires_room2():
    staging = case_staging_dir("mcp-a")
    staging.mkdir(parents=True)
    (staging / "sample.txt").write_text("hello", encoding="utf-8")
    intake_case("mcp-a")

    result = handle_run_sift_tool(
        tool_id="SIFT-008",
        case_id="mcp-a",
        input_relpath="sample.txt",
        purpose="identify file",
        why="test room gate",
    )
    assert result["ok"] is False
    assert "room" in result["error"].lower()


def test_run_sift_tool_file_on_sandbox(monkeypatch):
    staging = case_staging_dir("mcp-b")
    staging.mkdir(parents=True)
    (staging / "note.txt").write_text("plain text\n", encoding="utf-8")
    intake_case("mcp-b")
    bootstrap_case_to_room2("mcp-b")

    captured: list[list[str]] = []

    def fake_execute(cmd, **kwargs):
        captured.append(list(cmd))
        stdout_file = kwargs.get("stdout_file")
        if stdout_file is not None:
            stdout_file.parent.mkdir(parents=True, exist_ok=True)
            stdout_file.write_text("note.txt: ASCII text\n", encoding="utf-8")
        return {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": 0.01,
            "truncated": False,
        }

    monkeypatch.setattr("cold_box_room.r2.executor._execute", fake_execute)

    result = handle_run_sift_tool(
        tool_id="SIFT-008",
        case_id="mcp-b",
        input_relpath="note.txt",
        purpose="file type",
        why="verify harness wiring",
    )
    assert result["ok"] is True
    assert result["audit_id"].startswith("CB-")
    assert result["tool_id"] == "SIFT-008"
    assert captured
    assert captured[0][0].endswith("file")

    tool_log = (case_records_dir("mcp-b") / "tool_log.jsonl").read_text(encoding="utf-8")
    assert "SIFT-008" in tool_log
    audit = (case_records_dir("mcp-b") / "audit.jsonl").read_text(encoding="utf-8")
    assert result["audit_id"] in audit


def test_analyze_scratch_on_scratch_file(monkeypatch):
    staging = case_staging_dir("mcp-c")
    staging.mkdir(parents=True)
    (staging / "data.bin").write_bytes(b"SECRETTOKEN")
    intake_case("mcp-c")
    bootstrap_case_to_room2("mcp-c")

    target = scratch_dir("mcp-c") / "extracted.bin"
    target.write_bytes(b"SECRETTOKEN")

    class FakeProc:
        returncode = 0

        def __init__(self):
            self.stdout = self
            self.stderr = type("E", (), {"read": lambda self: b""})()

        def read(self, n=-1):
            return b""

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

        def kill(self):
            return None

    def fake_popen(cmd, **kwargs):
        return FakeProc()

    def fake_stream(pipe, out_path, **kwargs):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("SECRETTOKEN\n", encoding="utf-8")
        return 11, False

    monkeypatch.setattr("cold_box_room.r2.scratch_analysis.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "cold_box_room.r2.scratch_analysis.stream_pipe_to_file",
        fake_stream,
    )
    monkeypatch.setattr("cold_box_room.r2.output_files.count_lines", lambda path: 1)

    result = handle_analyze_scratch(
        case_id="mcp-c",
        binary="strings",
        scratch_relpath="extracted.bin",
        purpose="find token",
        why="test analyze wiring",
        args=["-n", "8"],
    )
    assert result["ok"] is True
    assert result["audit_id"].startswith("CB-")
    assert "SECRETTOKEN" in result["stdout_preview"]
