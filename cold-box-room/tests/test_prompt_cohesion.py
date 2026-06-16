"""Prompt cohesion — Room A inserted in hallway narrative."""

from cold_box_room.agent.prompts import (
    DEFAULT_LAYER1_GOAL,
    DEFAULT_ROOM_A_GOAL,
    LAYER1_SYSTEM_PROMPT,
    ROOM_A_SYSTEM_PROMPT,
)
from cold_box_room.agent.situation import format_room_a_briefing


def test_room_a_prompt_has_sandbox():
    text = ROOM_A_SYSTEM_PROMPT.lower()
    assert "list_sandbox_files" in text
    assert "room a" in text
    assert "formalize_plan_a" in text


def test_room_a_prompt_plan_only_no_sift_execution():
    text = ROOM_A_SYSTEM_PROMPT.lower()
    assert "plan only" in text or "do not run" in text


def test_layer1_prompt_room_a_before_sandbox():
    text = LAYER1_SYSTEM_PROMPT
    assert "Room A" in text
    assert "Room B" in text
    assert "only then" in text.lower() or "after room a" in text.lower()
    assert "Room 3" not in text.split("Room B")[0]  # no stale R3 as next room


def test_layer1_not_copied_on_r1_pass_alone():
    lower = LAYER1_SYSTEM_PROMPT.lower()
    assert "not on room 1 pass" in lower or "after room a" in lower


def test_layer1_mentions_extend_plan():
    assert "extend_plan_a_step" in LAYER1_SYSTEM_PROMPT
    assert "apply_plan_a_step_status" in LAYER1_SYSTEM_PROMPT


def test_layer1_goal_promote_to_room_b():
    assert "room b" in DEFAULT_LAYER1_GOAL.lower()
    assert "promote" in DEFAULT_LAYER1_GOAL.lower()


def test_default_goals_reference_room_a():
    assert "room a" in DEFAULT_LAYER1_GOAL.lower()
    assert "room 1" in DEFAULT_ROOM_A_GOAL.lower()
    assert "sandbox is ready" in DEFAULT_LAYER1_GOAL.lower()


def test_room_a_briefing_sandbox_available(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    records = tmp_path / "records"
    staging.mkdir()
    records.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(tmp_path / "r2-sandbox"))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))

    from cold_box_room.r1.intake import intake_case
    from cold_box_room.r1.hallway import promote_to_room_a
    from cold_box_room.r1.paths import case_staging_dir

    case_id = "prompt-a"
    d = case_staging_dir(case_id)
    d.mkdir(parents=True)
    (d / "disk.e01").write_bytes(b"x")
    intake_case(case_id)
    promote_to_room_a(case_id)

    text = format_room_a_briefing(case_id)
    assert "sandbox is available" in text.lower() or "list_sandbox_files" in text
    assert "r1 table" in text.lower()
    assert "disk.e01" in text
