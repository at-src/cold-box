"""Room 3 Layer 2 execution harness."""

from __future__ import annotations

import pytest

from cold_box_room.agent.tools import dispatch_tool
from cold_box_room.planning.guard import PlanningRoomGuardError, assert_tool_allowed_in_room
from cold_box_room.r1.hallway import current_room, return_to_room, unlocked_rooms
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import case_staging_dir
from cold_box_room.room_3 import apply_plan_b_step_status, room3_checkpoint, submit_layer2_writeup
from cold_box_room.room_3.skill_log import append_skill_log, read_skill_log
from cold_box_room.skills.registry import clear_registry_cache, list_skills
from cold_box_room.testing.hallway import bootstrap_case_to_room3


@pytest.fixture(autouse=True)
def _fresh_registry():
    clear_registry_cache()
    yield
    clear_registry_cache()


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


def test_agent_catalog_excludes_partial():
    all_runnable = list_skills(runnable_only=True)
    agent = list_skills(agent_catalog_only=True)
    assert len(all_runnable) == 213
    assert len(agent) == 171
    assert all(s.execution_mode != "partial" for s in agent)


def test_list_skills_dispatch_uses_agent_catalog():
    result = dispatch_tool("list_skills", {})
    assert result["count"] == 171


def test_return_to_room_and_back():
    case_id = "room3-revisit"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    assert current_room(case_id) == "3"
    assert "1" not in unlocked_rooms(case_id)

    back = return_to_room(case_id, "2", reason="Need another extraction before analysis step 1.")
    assert back["room"] == "2"
    assert_tool_allowed_in_room(tool_name="run_sift_tool", room="2")

    again = return_to_room(case_id, "3", reason="Extraction fixed; resuming analysis.")
    assert again["room"] == "3"


def test_return_to_room1_blocked():
    case_id = "room3-no-r1"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    from cold_box_room.r1.paths import StagingError

    with pytest.raises(StagingError, match="Room 1 is locked"):
        return_to_room(case_id, "1", reason="Trying to touch sealed evidence.")


def test_room3_checkpoint_blocks_without_skill_run():
    case_id = "room3-no-skill"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    cp = room3_checkpoint(case_id)
    assert cp["successful_skill_runs"] == 0
    assert cp["ready_for_complete"] is False
    assert "no_successful_skill_run" in cp["blocked_reasons"]


def test_submit_layer2_requires_corrections_after_revisit():
    case_id = "room3-corrections"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    return_to_room(case_id, "B", reason="Plan step 1 should target browser artifacts not registry.")
    return_to_room(case_id, "3", reason="Revised plan in Room B; resuming Layer 2 execution.")

    append_skill_log(
        case_id=case_id,
        run_id="CB-skill-test001",
        skill_id="SKILL-001",
        journal_id="CB-SKL-001",
        library_slug="cb-active-directory-compromise-investigation",
        input_relpath="disk.E01",
        ok=True,
        audit_ids=["CB-audit-test001"],
        exit_code=0,
    )
    apply_plan_b_step_status(
        case_id=case_id,
        step_id=1,
        status="passed",
        proof={"run_id": "CB-skill-test001"},
    )

    bad = submit_layer2_writeup(
        case_id=case_id,
        findings="Analysis complete on bootstrap plan.",
        self_score=9,
        why="Skill run logged and plan step passed.",
        corrections="none",
    )
    assert bad["complete"] is False
    assert "corrections_required_after_revisit" in bad["checkpoint"]["blocked_reasons"]

    good = submit_layer2_writeup(
        case_id=case_id,
        findings="Analysis complete after replanning in Room B.",
        self_score=9,
        why="Skill run logged; plan step 1 passed with corrected scope.",
        corrections=(
            "Returned to Room B because step 1 targeted registry only; "
            "revised plan to include browser timeline analysis."
        ),
    )
    assert good["complete"] is True
    assert good["ok"] is True
    cp = room3_checkpoint(case_id)
    assert cp["layer2_complete"] is True


def test_skill_log_readable():
    case_id = "room3-log"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    append_skill_log(
        case_id=case_id,
        run_id="CB-skill-log1",
        skill_id="SKILL-034",
        journal_id="CB-SKL-034",
        library_slug="cb-example",
        input_relpath="disk.E01",
        ok=True,
        audit_ids=["CB-x"],
        exit_code=0,
    )
    log = read_skill_log(case_id)
    assert log["count"] == 1
    assert log["successful_runs"] == 1


def test_held_for_later_blocks_complete():
    case_id = "room3-held"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    append_skill_log(
        case_id=case_id,
        run_id="CB-skill-held",
        skill_id="SKILL-001",
        journal_id="CB-SKL-001",
        library_slug="cb-active-directory-compromise-investigation",
        input_relpath="disk.E01",
        ok=True,
        audit_ids=["CB-audit-held"],
        exit_code=0,
    )
    apply_plan_b_step_status(
        case_id=case_id,
        step_id=1,
        status="held_for_later",
        proof={"note": "defer until second pass"},
    )
    result = submit_layer2_writeup(
        case_id=case_id,
        findings="Partial analysis.",
        self_score=9,
        why="One step still held.",
        corrections="none",
    )
    assert result["complete"] is False
    assert "plan_steps_unresolved" in result["checkpoint"]["blocked_reasons"]


def test_layer2_tool_log_heading():
    case_id = "room3-l2tool"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    from cold_box_room.room_3.tool_log import append_layer2_tool_log, read_layer2_tool_log

    append_layer2_tool_log(
        case_id=case_id,
        audit_id="CB-nested-1",
        tool_id="SIFT-008",
        tool_name="file",
        purpose="nested test",
        command=["file", "disk.E01"],
        input_relpath="disk.E01",
        exit_code=0,
        scratch_refs=["CB-nested-1/stdout.txt"],
        skill_id="SKILL-001",
        skill_run_id="CB-skill-n1",
        journal_id="CB-SKL-001",
    )
    log = read_layer2_tool_log(case_id)
    assert log["harness_only"] is True
    assert "# Layer 2 — Analysis (tool log)" in log["logbook_content"]


def test_run_skill_blocked_in_room_b():
    case_id = "room3-block-b"
    from cold_box_room.testing.hallway import bootstrap_case_to_room_b

    _intake(case_id)
    bootstrap_case_to_room_b(case_id)
    with pytest.raises(PlanningRoomGuardError):
        assert_tool_allowed_in_room(tool_name="run_skill", room="B")
