"""Layer 1 logbook — tool log, analyst log, promotion gates."""

import json

import pytest

from cold_box_room.r1.hallway import current_room
from cold_box_room.testing import bootstrap_case_to_room2
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import case_records_dir, case_staging_dir
from cold_box_room.r2.analyst_log import read_analyst_log, write_analyst_log
from cold_box_room.r2.checkpoint import exit_layer1, r2_layer1_checkpoint, submit_layer1_writeup
from cold_box_room.r2.layer1_state import load_layer1_state
from cold_box_room.r2.logbook_paths import layer1_analyst_log_md_path, layer1_tool_log_md_path
from cold_box_room.r2.tool_log import read_tool_log


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


def _promote_case(case_id: str, filename: str = "evidence.bin", content: bytes = b"x") -> None:
    staging = case_staging_dir(case_id)
    staging.mkdir(parents=True)
    (staging / filename).write_bytes(content)
    intake_case(case_id)
    bootstrap_case_to_room2(case_id)


def test_tool_logbook_md_created_on_append():
    from cold_box_room.r2.tool_log import append_tool_log

    _promote_case("log-a")
    append_tool_log(
        case_id="log-a",
        audit_id="CB-test123456",
        tool_id="SIFT-008",
        tool_name="file",
        purpose="type check",
        command=["file", "evidence.bin"],
        input_relpath="evidence.bin",
        exit_code=0,
        scratch_refs=["CB-test123456_SIFT-008_file/stdout.txt"],
        stdout_preview="evidence.bin: data",
    )
    md = layer1_tool_log_md_path("log-a").read_text(encoding="utf-8")
    assert "Layer 1 — Evidence extraction (tool log)" in md
    assert "CB-test123456" in md
    assert "SIFT-008" in md


def test_analyst_log_agent_only_format():
    _promote_case("log-b")
    write_analyst_log(
        case_id="log-b",
        findings="Found suspicious inode listing.",
        self_score=9,
        why="Clean extraction path with fls output.",
    )
    content = layer1_analyst_log_md_path("log-b").read_text(encoding="utf-8")
    assert "Layer 1 — Evidence extraction (analyst log)" in content
    assert "## Findings" in content
    assert "## Self-score" in content
    assert "## Why" in content
    parsed = read_analyst_log("log-b")["parsed"]
    assert parsed["complete"] is True
    assert parsed["self_score"] == 9


def test_submit_promotes_to_room3(monkeypatch):
    _promote_case("log-c")
    monkeypatch.setattr(
        "cold_box_room.r2.executor._execute",
        lambda cmd, **kwargs: {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": 0.01,
            "truncated": False,
            **(
                {"stdout_file": kwargs["stdout_file"]}
                if kwargs.get("stdout_file")
                else {}
            ),
        },
    )
    from cold_box_room.r2.executor import run_sift_tool

    run_sift_tool(
        tool_id="SIFT-008",
        case_id="log-c",
        input_relpath="evidence.bin",
        purpose="file",
        why="setup extraction gate",
    )

    result = submit_layer1_writeup(
        case_id="log-c",
        findings="Recovered file metadata from evidence.",
        self_score=9,
        why="Successful file tool run with scratch output.",
    )
    assert result["promoted"] is True
    assert current_room("log-c") == "B"


def test_low_score_increments_attempts():
    _promote_case("log-d")
    from cold_box_room.r2.tool_log import append_tool_log

    append_tool_log(
        case_id="log-d",
        audit_id="CB-aaa",
        tool_id="SIFT-008",
        tool_name="file",
        purpose="x",
        command=["file", "x"],
        input_relpath="evidence.bin",
        exit_code=0,
        scratch_refs=["out.txt"],
        stdout_preview="ok",
    )
    result = submit_layer1_writeup(
        case_id="log-d",
        findings="Partial work.",
        self_score=7,
        why="Still missing registry extraction.",
    )
    assert result["promoted"] is False
    assert "self_score_not_above_8" in result["blocked_reasons"]
    assert load_layer1_state("log-d")["promotion_attempts"] == 1


def test_extraction_gate_blocks_without_tool_run():
    _promote_case("log-e")
    result = submit_layer1_writeup(
        case_id="log-e",
        findings="Nothing extracted yet.",
        self_score=10,
        why="Premature submit.",
    )
    assert result["promoted"] is False
    assert "no_successful_extraction" in result["blocked_reasons"]


def test_exit_layer1_after_three_attempts():
    _promote_case("log-f")
    from cold_box_room.r2.tool_log import append_tool_log

    append_tool_log(
        case_id="log-f",
        audit_id="CB-bbb",
        tool_id="SIFT-008",
        tool_name="file",
        purpose="x",
        command=["file", "x"],
        input_relpath="evidence.bin",
        exit_code=0,
        scratch_refs=["out.txt"],
        stdout_preview="ok",
    )
    for _ in range(3):
        submit_layer1_writeup(
            case_id="log-f",
            findings="Still incomplete.",
            self_score=6,
            why="Need more artifacts.",
        )
    result = exit_layer1(
        case_id="log-f",
        reason="Cannot reach score above 8 without registry hive extraction.",
    )
    assert result["exited"] is True
    assert current_room("log-f") == "2"
    checkpoint = r2_layer1_checkpoint("log-f")
    assert checkpoint["exited"] is True


def test_r2_layer1_checkpoint_json():
    _promote_case("log-g")
    checkpoint = r2_layer1_checkpoint("log-g")
    assert checkpoint["successful_extractions"] == 0
    assert checkpoint["ready_for_room_b"] is False
