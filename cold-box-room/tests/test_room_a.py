"""Room A — write md → formalize py (shared planning blueprint)."""

from __future__ import annotations

import pytest

from cold_box_room.planning.guard import PlanningRoomGuardError, assert_tool_allowed_in_room
from cold_box_room.planning.harness import PlanHarnessError, apply_step_status
from cold_box_room.planning.plan_py import load_plan_py
from cold_box_room.planning.scoring import all_steps_resolved, compute_plan_score
from cold_box_room.room_a import (
    formalize_plan_a,
    plan_a_md_path,
    plan_a_py_path,
    room_a_checkpoint,
    write_plan_a_md,
)


@pytest.fixture(autouse=True)
def _isolated_records(tmp_path, monkeypatch):
    records = tmp_path / "records"
    records.mkdir()
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))


def _sample_plan_md(case_id: str) -> str:
    return f"""# Extraction plan — `{case_id}`

## Step 1 — Image metadata

**Reason:** Establish chain of custody and partition layout

## Step 2 — Filesystem listing

**Reason:** Inventory user profiles and high-value paths

## Step 3 — Mail stores if present

**Reason:** Outlook Express mail stores if this case has them — mark not_relevant in R2 otherwise
"""


def _pass_proof(audit_id: str = "CB-a1") -> dict:
    return {
        "audit_id": audit_id,
        "exit_code": 0,
        "scratch_refs": [f"{audit_id}_out/stdout.txt"],
    }


def _room_a_complete(case_id: str) -> None:
    write_plan_a_md(case_id=case_id, markdown=_sample_plan_md(case_id))
    formalize_plan_a(case_id=case_id)


class TestRoomAWorkflow:
    def test_full_flow_opens_gate_on_formalize(self):
        case_id = "workflow-fake"
        write_plan_a_md(case_id=case_id, markdown=_sample_plan_md(case_id))
        assert plan_a_md_path(case_id).is_file()

        cp_before = room_a_checkpoint(case_id)
        assert cp_before["ready_for_room2"] is False
        assert "plan_not_formalized" in cp_before["blocked_reasons"]

        formalized = formalize_plan_a(case_id=case_id)
        assert formalized["plan_formalized"] is True
        assert formalized["ready_for_room2"] is True
        assert plan_a_py_path(case_id).is_file()

        ready = room_a_checkpoint(case_id)
        assert ready["plan_formalized"] is True
        assert ready["ready_for_room2"] is True
        assert ready["blocked_reasons"] == []

        py_doc = load_plan_py(plan_a_py_path(case_id), room="a")
        assert all(s.status == "pending" for s in py_doc.steps)
        assert all(s.tool_id == "" for s in py_doc.steps)

    def test_gate_closed_before_formalize(self):
        case_id = "no-formalize"
        write_plan_a_md(case_id=case_id, markdown=_sample_plan_md(case_id))

        cp = room_a_checkpoint(case_id)
        assert cp["ready_for_room2"] is False
        assert "plan_not_formalized" in cp["blocked_reasons"]

    def test_write_rejects_empty_steps(self):
        case_id = "no-steps"
        md = """# Extraction plan — `no-steps`
"""
        with pytest.raises(Exception, match="Step N"):
            write_plan_a_md(case_id=case_id, markdown=md)

    def test_formalize_preserves_r2_execution_status(self):
        case_id = "preserve"
        _room_a_complete(case_id)
        apply_step_status(
            case_id=case_id,
            room="a",
            step_id=1,
            status="passed",
            proof=_pass_proof("CB-keep"),
            allowed_session_audit_ids={"CB-keep"},
        )
        write_plan_a_md(case_id=case_id, markdown=_sample_plan_md(case_id))
        formalize_plan_a(case_id=case_id)
        doc = load_plan_py(plan_a_py_path(case_id), room="a")
        assert doc.steps[0].status == "passed"


class TestPlanningGuard:
    def test_blocks_extraction_tools_in_room_a(self):
        with pytest.raises(PlanningRoomGuardError, match="run_sift_tool"):
            assert_tool_allowed_in_room(tool_name="run_sift_tool", room="A")

    def test_allows_catalog_in_room_a(self):
        assert_tool_allowed_in_room(tool_name="list_sift_tools", room="A") is None


class TestR2PlanScoring:
    def test_pass_fail_on_formalized_plan(self):
        case_id = "score-me"
        _room_a_complete(case_id)
        audits = {"CB-1", "CB-2", "CB-3"}

        apply_step_status(
            case_id=case_id,
            room="a",
            step_id=1,
            status="passed",
            proof=_pass_proof("CB-1"),
            allowed_session_audit_ids=audits,
        )
        apply_step_status(
            case_id=case_id,
            room="a",
            step_id=2,
            status="passed",
            proof=_pass_proof("CB-2"),
            allowed_session_audit_ids=audits,
        )
        apply_step_status(
            case_id=case_id,
            room="a",
            step_id=3,
            status="not_relevant",
            proof={"note": "No mail client on this memory image"},
        )

        doc = load_plan_py(plan_a_py_path(case_id), room="a")
        score = compute_plan_score(doc)
        assert score["scoring_pool_size"] == 2
        assert score["plan_score_pct"] == 100.0
        assert all_steps_resolved(doc) is True

    def test_pass_requires_audit_proof(self):
        case_id = "bad-proof"
        _room_a_complete(case_id)
        with pytest.raises(PlanHarnessError, match="audit_id"):
            apply_step_status(case_id=case_id, room="a", step_id=1, status="passed", proof={})
