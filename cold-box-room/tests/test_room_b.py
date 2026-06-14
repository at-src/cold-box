"""Room B — write md → formalize py (shared planning blueprint)."""

from __future__ import annotations

import pytest

from cold_box_room.planning.guard import PlanningRoomGuardError, assert_tool_allowed_in_room
from cold_box_room.room_b import (
    formalize_plan_b,
    plan_b_md_path,
    plan_b_py_path,
    room_b_checkpoint,
    write_plan_b_md,
)
from cold_box_room.testing import bootstrap_case_to_room_b


@pytest.fixture(autouse=True)
def _isolated_records(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    sandbox = tmp_path / "r2-sandbox"
    records = tmp_path / "records"
    for path in (staging, sandbox, records):
        path.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(sandbox))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))


def _sample_plan_md(case_id: str) -> str:
    return f"""# Analysis plan — `{case_id}`

## Step 1 — Correlate browser artifacts with patentauto.py

**Reason:** Layer 1 extracted patentauto.py and IE history — need structured timeline of USPTO activity

## Step 2 — USB exfiltration chain

**Reason:** IE history and LNK files reference E: drive — analysis should tie USB serial to file access
"""


def _intake(case_id: str) -> None:
    from cold_box_room.r1.intake import intake_case
    from cold_box_room.r1.paths import case_staging_dir

    staging = case_staging_dir(case_id)
    staging.mkdir(parents=True)
    (staging / "disk.E01").write_bytes(b"evidence")
    intake_case(case_id)


class TestRoomBWorkflow:
    def test_full_flow_opens_gate_on_formalize(self):
        case_id = "room-b-flow"
        _intake(case_id)
        bootstrap_case_to_room_b(case_id)

        write_plan_b_md(case_id=case_id, markdown=_sample_plan_md(case_id))
        assert plan_b_md_path(case_id).is_file()

        cp_before = room_b_checkpoint(case_id)
        assert cp_before["ready_for_room3"] is False
        assert "plan_not_formalized" in cp_before["blocked_reasons"]

        formalized = formalize_plan_b(case_id=case_id)
        assert formalized["plan_formalized"] is True
        assert formalized["ready_for_room3"] is True
        assert plan_b_py_path(case_id).is_file()

        ready = room_b_checkpoint(case_id)
        assert ready["plan_formalized"] is True
        assert ready["ready_for_room3"] is True
        assert ready["blocked_reasons"] == []

    def test_blocks_extraction_in_room_b(self):
        with pytest.raises(PlanningRoomGuardError, match="run_sift_tool"):
            assert_tool_allowed_in_room(tool_name="run_sift_tool", room="B")

    def test_allows_layer1_read_tools_in_room_b(self):
        assert_tool_allowed_in_room(tool_name="read_layer1_tool_log", room="B") is None
        assert_tool_allowed_in_room(tool_name="write_plan_b_md", room="B") is None
