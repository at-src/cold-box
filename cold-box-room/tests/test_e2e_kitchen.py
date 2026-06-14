"""E2E kitchen (R1→R2) — no live LLM."""

from pathlib import Path

import pytest

from cold_box_room.agent.prompts import DEFAULT_LAYER1_GOAL, LAYER1_SYSTEM_PROMPT
from cold_box_room.e2e.run_layer1 import deliver_to_room2, prepare_fresh_workspace
from cold_box_room.r1.hallway import current_room
from cold_box_room.r2.sandbox import list_sandbox_files


@pytest.fixture
def jo_or_skip(tmp_path):
    jo = Path("/opt/cold-box-final/operation-table/m57-jo/jo-2009-12-11-002.E01")
    if not jo.is_file():
        pytest.skip("Jo E01 not on this host")
    return jo


def test_system_prompt_does_not_list_catalog_tools():
    assert "SIFT-" not in LAYER1_SYSTEM_PROMPT
    assert "list_sift_tools" not in LAYER1_SYSTEM_PROMPT
    assert "mmls" not in LAYER1_SYSTEM_PROMPT.lower()


def test_system_prompt_states_r2_to_room_b_promotion_gates():
    assert "Room B" in LAYER1_SYSTEM_PROMPT
    assert "Room A" in LAYER1_SYSTEM_PROMPT
    assert "Room 1" in LAYER1_SYSTEM_PROMPT
    assert "sealed" in LAYER1_SYSTEM_PROMPT.lower()
    assert "investigation" in LAYER1_SYSTEM_PROMPT.lower()
    assert "self_score" in LAYER1_SYSTEM_PROMPT
    assert "1–10" in LAYER1_SYSTEM_PROMPT or "1 to 10" in LAYER1_SYSTEM_PROMPT
    assert "submit_layer1_writeup" in LAYER1_SYSTEM_PROMPT
    assert "get_layer1_status" in LAYER1_SYSTEM_PROMPT


def test_default_goal_is_non_prescriptive():
    assert "mmls" not in DEFAULT_LAYER1_GOAL.lower()
    assert "sqlite" not in DEFAULT_LAYER1_GOAL.lower()


def test_kitchen_r1_to_r2(tmp_path, jo_or_skip, monkeypatch):
    run_id = "test-kitchen"
    prepare_fresh_workspace(run_id=str(tmp_path / run_id), wipe=True)
    result = deliver_to_room2(
        case_id="test-case",
        evidence_path=jo_or_skip,
        link_only=True,
        skip_room_a_agent=True,
    )
    assert result["ok"] is True
    assert result["room"] == "2"
    assert current_room("test-case") == "2"
    files = list_sandbox_files("test-case")
    assert any("jo-2009-12-11-002.E01" in f.get("path", f.get("relpath", "")) for f in files)
