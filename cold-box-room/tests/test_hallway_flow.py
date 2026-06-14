"""Hallway sanity — R1 → A → R2 → B entrance."""

from __future__ import annotations

import pytest

from cold_box_room.planning.guard import PlanningRoomGuardError, assert_tool_allowed_in_room
from cold_box_room.r1.hallway import (
    current_room,
    promote_to_room2,
    promote_to_room_a,
    promote_to_room_b,
    promote_to_room3,
)
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import StagingError, case_staging_dir
from cold_box_room.r2.checkpoint import r2_layer1_checkpoint, submit_layer1_writeup
from cold_box_room.r2.tool_log import append_tool_log
from cold_box_room.room_a import (
    extend_plan_a_step,
    fast_pass_room_a,
    formalize_plan_a,
    room_a_checkpoint,
    write_plan_a_md,
)
from cold_box_room.room_b import fast_pass_room_b, formalize_plan_b, room_b_checkpoint, write_plan_b_md
from cold_box_room.testing import bootstrap_case_to_room2


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


def _intake(case_id: str) -> None:
    staging = case_staging_dir(case_id)
    staging.mkdir(parents=True)
    (staging / "disk.E01").write_bytes(b"evidence")
    intake_case(case_id)


def test_hallway_r1_to_room_b_entrance():
    case_id = "hallway-full"
    _intake(case_id)
    assert current_room(case_id) == "1"

    promote_to_room_a(case_id)
    assert current_room(case_id) == "A"

    gate = fast_pass_room_a(case_id)
    assert gate["gate_open"] is True
    promote_to_room2(case_id)
    assert current_room(case_id) == "2"

    append_tool_log(
        case_id=case_id,
        audit_id="CB-h1",
        tool_id="SIFT-001",
        tool_name="mmls",
        purpose="test extraction",
        command=["mmls", "disk.E01"],
        input_relpath="disk.E01",
        exit_code=0,
        scratch_refs=["CB-h1_out/stdout.txt"],
    )
    result = submit_layer1_writeup(
        case_id=case_id,
        findings="Extracted disk metadata.",
        self_score=9,
        why="Solid baseline extraction.",
    )
    assert result["promoted"] is True
    assert current_room(case_id) == "B"


def test_hallway_room_b_to_room3_entrance():
    case_id = "hallway-b-c"
    _intake(case_id)
    promote_to_room_a(case_id)
    fast_pass_room_a(case_id)
    promote_to_room2(case_id)
    append_tool_log(
        case_id=case_id,
        audit_id="CB-h2",
        tool_id="SIFT-001",
        tool_name="mmls",
        purpose="test extraction",
        command=["mmls", "disk.E01"],
        input_relpath="disk.E01",
        exit_code=0,
        scratch_refs=["CB-h2_out/stdout.txt"],
    )
    submit_layer1_writeup(
        case_id=case_id,
        findings="Extracted disk metadata.",
        self_score=9,
        why="Solid baseline extraction.",
    )
    assert current_room(case_id) == "B"

    write_plan_b_md(
        case_id=case_id,
        markdown="""# Analysis plan — `hallway-b-c`

## Step 1 — Timeline synthesis

**Reason:** Merge prefetch, LNK, and browser artifacts into incident-day sequence
""",
    )
    assert room_b_checkpoint(case_id)["ready_for_room3"] is False
    formalize_plan_b(case_id=case_id)
    assert room_b_checkpoint(case_id)["ready_for_room3"] is True
    promote_to_room3(case_id)
    assert current_room(case_id) == "3"


def test_formalize_opens_room2_gate():
    case_id = "formalize-gate"
    _intake(case_id)
    promote_to_room_a(case_id)
    write_plan_a_md(
        case_id=case_id,
        markdown="""# Extraction plan — `formalize-gate`

## Step 1 — Metadata

**Reason:** Chain of custody
""",
    )
    cp_before = room_a_checkpoint(case_id)
    assert cp_before["ready_for_room2"] is False

    result = formalize_plan_a(case_id=case_id)
    assert result["ready_for_room2"] is True
    assert room_a_checkpoint(case_id)["ready_for_room2"] is True


def test_extend_plan_in_r2_scores_new_step():
    case_id = "extend-r2"
    _intake(case_id)
    bootstrap_case_to_room2(case_id)

    added = extend_plan_a_step(
        case_id=case_id,
        title="Outlook Express mail",
        reason="Found dbx references during filesystem sweep",
    )
    assert added["step_id"] == 3
    assert added["status"] == "pending"

    with pytest.raises(PlanningRoomGuardError):
        assert_tool_allowed_in_room(tool_name="write_plan_a_md", room="2")

    with pytest.raises(PlanningRoomGuardError):
        assert_tool_allowed_in_room(tool_name="run_sift_tool", room="A")


def test_room2_blocked_without_room_a_gate():
    case_id = "skip-a"
    _intake(case_id)
    promote_to_room_a(case_id)
    write_plan_a_md(
        case_id=case_id,
        markdown="""# Extraction plan — `skip-a`

## Step 1 — Metadata

**Reason:** Chain of custody
""",
    )
    with pytest.raises(StagingError, match="Room A checkpoint failed"):
        promote_to_room2(case_id)
