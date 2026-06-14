"""R2 executor — subprocess harness."""

import json

import pytest

from cold_box_room.testing import bootstrap_case_to_room2
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import case_records_dir, case_staging_dir
from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.executor import run_sift_tool


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


def test_tsk_recover_appends_output_dir(monkeypatch):
    staging = case_staging_dir("recover")
    staging.mkdir(parents=True)
    (staging / "disk.dd").write_bytes(b"fake-image")
    intake_case("recover")
    bootstrap_case_to_room2("recover")

    captured: list[list[str]] = []

    def fake_execute(cmd, **kwargs):
        captured.append(list(cmd))
        stdout_file = kwargs.get("stdout_file")
        if stdout_file is not None:
            stdout_file.parent.mkdir(parents=True, exist_ok=True)
            stdout_file.write_text("ok\n", encoding="utf-8")
        return {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": 0.01,
            "truncated": False,
        }

    monkeypatch.setattr("cold_box_room.r2.executor._execute", fake_execute)

    result = run_sift_tool(
        tool_id="SIFT-164",
        case_id="recover",
        input_relpath="disk.dd",
        purpose="bulk recover",
        why="test scratch_dir_trailing",
        extra_args=["-o", "63"],
    )
    assert result["ok"] is True
    assert captured
    assert captured[0][-1].endswith("/output")


def test_blocks_unavailable_tool():
    staging = case_staging_dir("blocked")
    staging.mkdir(parents=True)
    (staging / "x").write_bytes(b"1")
    intake_case("blocked")
    bootstrap_case_to_room2("blocked")

    with pytest.raises(ToolExecutionError, match="not installed"):
        run_sift_tool(
            tool_id="SIFT-221",
            case_id="blocked",
            input_relpath="x",
            purpose="prefetch",
            why="should fail",
        )


def test_tool_log_written(monkeypatch):
    staging = case_staging_dir("logged")
    staging.mkdir(parents=True)
    (staging / "a.txt").write_text("hi", encoding="utf-8")
    intake_case("logged")
    bootstrap_case_to_room2("logged")

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

    result = run_sift_tool(
        tool_id="SIFT-008",
        case_id="logged",
        input_relpath="a.txt",
        purpose="file",
        why="log test",
    )
    rows = [
        json.loads(line)
        for line in (case_records_dir("logged") / "tool_log.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert rows[-1]["audit_id"] == result["audit_id"]
    assert rows[-1]["exit_code"] == 0
