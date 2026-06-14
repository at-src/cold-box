"""R2→R3 wall — fake evidence, checklist gates, promote only when all pass."""

from __future__ import annotations

import pytest

from cold_box_room.r1.hallway import current_room, promote_to_room_a, promote_to_room_b, promote_to_room3
from cold_box_room.testing import bootstrap_case_to_room2
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import StagingError, case_staging_dir
from cold_box_room.r2.analyst_log import AnalystLogError
from cold_box_room.r2.checkpoint import r2_layer1_checkpoint, submit_layer1_writeup
from cold_box_room.r2.tool_log import append_tool_log


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


def _case_in_room2(case_id: str, *, evidence: bytes = b"FAKE-EVIDENCE-v1") -> None:
    staging = case_staging_dir(case_id)
    staging.mkdir(parents=True)
    (staging / "fake-disk.e01").write_bytes(evidence)
    intake_case(case_id)
    bootstrap_case_to_room2(case_id)
    assert current_room(case_id) == "2"


def _successful_extraction(case_id: str, *, audit_id: str = "CB-gate-ok") -> None:
    append_tool_log(
        case_id=case_id,
        audit_id=audit_id,
        tool_id="SIFT-008",
        tool_name="file",
        purpose="Type fake evidence",
        command=["file", "fake-disk.e01"],
        input_relpath="fake-disk.e01",
        exit_code=0,
        scratch_refs=[f"{audit_id}_SIFT-008_file/stdout.txt"],
        stdout_preview="fake-disk.e01: data",
    )


def _good_submit_kwargs() -> dict:
    return {
        "findings": "Fake evidence typed as data; inode listing captured in scratch.",
        "self_score": 9,
        "why": "One clean extraction with scratch output; findings match tool log.",
    }


class TestR2R3GateWall:
    """Harness wall: extraction + analyst write-up + self_score > 8."""

    def test_all_gates_pass_promotes_to_room3(self):
        case_id = "gate-pass"
        _case_in_room2(case_id)
        _successful_extraction(case_id)

        checkpoint = r2_layer1_checkpoint(case_id)
        assert checkpoint["extraction_gate"] is True
        assert checkpoint["analyst_log"] is None
        assert checkpoint["ready_for_room_b"] is False
        assert "analyst_log_incomplete" in checkpoint["blocked_reasons"]

        result = submit_layer1_writeup(case_id=case_id, **_good_submit_kwargs())
        assert result["ok"] is True
        assert result["promoted"] is True
        assert result["room"] == "B"
        assert current_room(case_id) == "B"

        with pytest.raises(StagingError, match="required room 2"):
            r2_layer1_checkpoint(case_id)

    def test_blocks_without_successful_extraction(self):
        case_id = "gate-no-extract"
        _case_in_room2(case_id)

        checkpoint = r2_layer1_checkpoint(case_id)
        assert checkpoint["successful_extractions"] == 0
        assert checkpoint["ready_for_room_b"] is False
        assert "no_successful_extraction" in checkpoint["blocked_reasons"]

        result = submit_layer1_writeup(case_id=case_id, **_good_submit_kwargs())
        assert result["promoted"] is False
        assert result["room"] == 2
        assert current_room(case_id) == "2"
        assert "no_successful_extraction" in result["blocked_reasons"]

    def test_blocks_score_equal_to_8(self):
        case_id = "gate-score-8"
        _case_in_room2(case_id)
        _successful_extraction(case_id)

        result = submit_layer1_writeup(
            case_id=case_id,
            findings="Some findings.",
            self_score=8,
            why="Good but not confident enough for 9.",
        )
        assert result["promoted"] is False
        assert current_room(case_id) == "2"
        assert "self_score_not_above_8" in result["blocked_reasons"]

    def test_blocks_score_below_8(self):
        case_id = "gate-score-low"
        _case_in_room2(case_id)
        _successful_extraction(case_id)

        result = submit_layer1_writeup(
            case_id=case_id,
            findings="Partial findings only.",
            self_score=6,
            why="Missing browser history and registry.",
        )
        assert result["promoted"] is False
        assert "self_score_not_above_8" in result["blocked_reasons"]

    def test_failed_tool_run_does_not_count_as_extraction(self):
        case_id = "gate-fail-exit"
        _case_in_room2(case_id)
        append_tool_log(
            case_id=case_id,
            audit_id="CB-bad",
            tool_id="SIFT-032",
            tool_name="bulk_extractor",
            purpose="carve",
            command=["bulk_extractor", "x"],
            input_relpath="fake-disk.e01",
            exit_code=1,
            scratch_refs=["CB-bad/stderr.txt"],
            stdout_preview="",
            error="compiled without E01 support",
        )

        checkpoint = r2_layer1_checkpoint(case_id)
        assert checkpoint["successful_extractions"] == 0
        assert "no_successful_extraction" in checkpoint["blocked_reasons"]

    def test_extraction_needs_scratch_or_preview(self):
        case_id = "gate-empty-output"
        _case_in_room2(case_id)
        append_tool_log(
            case_id=case_id,
            audit_id="CB-empty",
            tool_id="SIFT-008",
            tool_name="file",
            purpose="x",
            command=["file", "x"],
            input_relpath="fake-disk.e01",
            exit_code=0,
            scratch_refs=[],
            stdout_preview="",
        )

        checkpoint = r2_layer1_checkpoint(case_id)
        assert checkpoint["successful_extractions"] == 0

    def test_analyze_scratch_counts_toward_extraction_gate(self):
        case_id = "gate-scratch"
        _case_in_room2(case_id)
        append_tool_log(
            case_id=case_id,
            audit_id="CB-grep1",
            tool_id="SCRATCH",
            tool_name="grep",
            purpose="filter listing",
            command=["grep", "patent", "listing.txt"],
            input_relpath="CB-listing/stdout.txt",
            exit_code=0,
            scratch_refs=["CB-grep1_scratch_grep/stdout.txt"],
            stdout_preview="patent001.txt",
        )

        result = submit_layer1_writeup(case_id=case_id, **_good_submit_kwargs())
        assert result["promoted"] is True
        assert current_room(case_id) == "B"

    def test_blocks_without_resolved_plan(self):
        case_id = "gate-plan-pending"
        staging = case_staging_dir(case_id)
        staging.mkdir(parents=True)
        (staging / "fake-disk.e01").write_bytes(b"FAKE-EVIDENCE-v1")
        intake_case(case_id)
        promote_to_room_a(case_id)
        from cold_box_room.room_a import formalize_plan_a, write_plan_a_md

        write_plan_a_md(
            case_id=case_id,
            markdown="""# Extraction plan — `gate-plan-pending`

## Step 1 — Metadata

**Reason:** Chain of custody
""",
        )
        formalize_plan_a(case_id=case_id)
        from cold_box_room.r1.hallway import promote_to_room2

        promote_to_room2(case_id)
        _successful_extraction(case_id)

        checkpoint = r2_layer1_checkpoint(case_id)
        assert checkpoint["plan_resolved_gate"] is False
        assert "plan_steps_unresolved" in checkpoint["blocked_reasons"]

        result = submit_layer1_writeup(case_id=case_id, **_good_submit_kwargs())
        assert result["promoted"] is False
        assert "plan_steps_unresolved" in result["blocked_reasons"]

    def test_promote_to_room3_direct_call_blocked_by_wall(self):
        case_id = "gate-direct-promote"
        _case_in_room2(case_id)

        with pytest.raises(StagingError, match="required room B"):
            promote_to_room3(case_id)
        assert current_room(case_id) == "2"

    def test_empty_findings_rejected_before_promotion(self):
        case_id = "gate-empty-findings"
        _case_in_room2(case_id)
        _successful_extraction(case_id)

        with pytest.raises(AnalystLogError, match="findings must not be empty"):
            submit_layer1_writeup(
                case_id=case_id,
                findings="   ",
                self_score=10,
                why="Should not promote.",
            )
        assert current_room(case_id) == "2"

    def test_checklist_matrix_before_submit(self):
        """Single case stepping through gate states like a manual checklist."""
        case_id = "gate-matrix"
        _case_in_room2(case_id)

        # Step 1 — nothing done yet
        c1 = r2_layer1_checkpoint(case_id)
        assert c1["extraction_gate"] is False
        assert c1["score_gate"] is False
        assert c1["ready_for_room_b"] is False
        assert set(c1["blocked_reasons"]) >= {"no_successful_extraction", "analyst_log_incomplete"}

        # Step 2 — extraction only
        _successful_extraction(case_id)
        c2 = r2_layer1_checkpoint(case_id)
        assert c2["extraction_gate"] is True
        assert c2["ready_for_room_b"] is False
        assert "analyst_log_incomplete" in c2["blocked_reasons"]

        # Step 3 — submit with low score (wall holds)
        low = submit_layer1_writeup(
            case_id=case_id,
            findings="Extracted file type only.",
            self_score=7,
            why="Not enough artifact depth for Layer 2 yet.",
        )
        assert low["promoted"] is False
        assert "self_score_not_above_8" in low["blocked_reasons"]
        assert current_room(case_id) == "2"

        # Step 4 — full checklist pass
        high = submit_layer1_writeup(
            case_id=case_id,
            findings="Extracted file type; sufficient Layer 1 scope for planning.",
            self_score=9,
            why="Extraction succeeded; findings documented; ready for Room 3 planning.",
        )
        assert high["promoted"] is True
        assert current_room(case_id) == "B"
