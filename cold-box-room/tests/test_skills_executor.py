"""Skill harness execution in Room 3."""

import pytest

from cold_box_room.agent.tools import dispatch_tool
from cold_box_room.planning.guard import PlanningRoomGuardError, assert_tool_allowed_in_room
from cold_box_room.r1.hallway import current_room
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import case_staging_dir
from cold_box_room.skills.executor import run_skill
from cold_box_room.skills.registry import clear_registry_cache
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


def test_reference_skill_cannot_run():
    case_id = "skill-ref-blocked"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)

    result = run_skill(
        skill_id="SKILL-002",
        case_id=case_id,
        input_relpath="disk.E01",
    )
    assert result["ok"] is False
    assert result["reference_only"] is True


def test_runnable_skill_requires_input_relpath():
    case_id = "skill-input-required"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)

    result = run_skill(skill_id="SKILL-001", case_id=case_id, input_relpath="")
    assert result["ok"] is False
    assert "input_relpath" in result["error"]


def test_run_skill_blocked_outside_room3():
    case_id = "skill-blocked"
    _intake(case_id)
    with pytest.raises(Exception):
        run_skill(skill_id="SKILL-001", case_id=case_id, input_relpath="disk.E01")


def test_room_b_can_browse_not_run():
    case_id = "skill-browse"
    _intake(case_id)
    from cold_box_room.testing.hallway import bootstrap_case_to_room_b

    bootstrap_case_to_room_b(case_id)
    assert current_room(case_id) == "B"
    assert_tool_allowed_in_room(tool_name="list_skills", room="B")
    assert_tool_allowed_in_room(tool_name="describe_skill", room="B")
    with pytest.raises(PlanningRoomGuardError):
        assert_tool_allowed_in_room(tool_name="run_skill", room="B")


def test_dispatch_list_skills_in_room_b():
    case_id = "skill-dispatch-b"
    _intake(case_id)
    from cold_box_room.testing.hallway import bootstrap_case_to_room_b

    bootstrap_case_to_room_b(case_id)
    result = dispatch_tool("list_skills", {"case_id": case_id})
    assert result["count"] == 50
    assert result["skills"][0]["skill_id"] == "SKILL-001"
    assert "has_script" in result["skills"][0]
