"""Hallway E2E orchestrator — no live LLM."""

from pathlib import Path

import pytest

from cold_box_room.e2e.report import collect_case_report
from cold_box_room.e2e.run_hallway import run_hallway_e2e
from cold_box_room.r1.hallway import current_room
from cold_box_room.room_3 import apply_plan_b_step_status, submit_layer2_writeup
from cold_box_room.room_3.skill_log import append_skill_log
from cold_box_room.testing.hallway import bootstrap_case_to_room3


@pytest.fixture
def jo_or_skip(tmp_path):
    jo = Path("/opt/cold-box-final/operation-table/m57-jo/jo-2009-12-11-002.E01")
    if not jo.is_file():
        pytest.skip("Jo E01 not on this host")
    return jo


def test_hallway_kitchen_only(tmp_path, jo_or_skip, monkeypatch):
    run_id = str(tmp_path / "hallway-kitchen")
    prepare = run_hallway_e2e(
        run_id=run_id,
        case_id="hallway-kitchen-case",
        evidence_path=jo_or_skip,
        run_agents=False,
    )
    assert prepare["status"] == "kitchen_done"
    assert current_room("hallway-kitchen-case") == "A"
    report = prepare["report"]
    assert report["case_id"] == "hallway-kitchen-case"
    assert report["complete"] is False


def test_hallway_fast_pass_to_room3_entrance(tmp_path, jo_or_skip, monkeypatch):
    run_id = str(tmp_path / "hallway-fast")
    out = run_hallway_e2e(
        run_id=run_id,
        case_id="hallway-fast-case",
        evidence_path=jo_or_skip,
        skip_room_a_agent=True,
        skip_layer1_agent=True,
        skip_room_b_agent=True,
        skip_room3_agent=True,
    )
    assert current_room("hallway-fast-case") == "3"
    assert out["status"] == "incomplete"
    report = out["report"]
    assert report["room"] == "3"
    assert report["plans"]["plan_b_md"] is not None


def test_collect_case_report_after_layer2_complete(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    sandbox = tmp_path / "r2-sandbox"
    records = tmp_path / "records"
    staging.mkdir()
    sandbox.mkdir()
    records.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(sandbox))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))

    from cold_box_room.r1.intake import intake_case
    from cold_box_room.r1.paths import case_staging_dir

    case_id = "report-complete"
    d = case_staging_dir(case_id)
    d.mkdir(parents=True)
    (d / "disk.e01").write_bytes(b"E01")
    intake_case(case_id)
    bootstrap_case_to_room3(case_id)

    append_skill_log(
        case_id=case_id,
        run_id="CB-report-test",
        skill_id="SKILL-001",
        journal_id="CB-SKL-report",
        library_slug="cb-windows-registry-for-artifacts",
        input_relpath="disk.e01",
        ok=True,
        audit_ids=["CB-audit-report"],
        exit_code=0,
        purpose="report test",
        why="bootstrap skill run for report collector",
    )
    apply_plan_b_step_status(
        case_id=case_id,
        step_id=1,
        status="passed",
        proof={"run_id": "CB-report-test"},
    )
    submit_layer2_writeup(
        case_id=case_id,
        findings="Registry analysis complete.",
        self_score=9,
        why="Skill run succeeded with harness proof.",
        corrections="none",
    )

    report = collect_case_report(case_id)
    assert report["complete"] is True
    assert report["layer2"]["findings"] is not None
    assert report["layer1"]["findings"] is not None
