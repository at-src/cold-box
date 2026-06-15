"""Tests for plan_py serialization."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from cold_box_room.planning.extend import extend_plan_step
from cold_box_room.planning.harness import apply_step_status
from cold_box_room.planning.plan_py import load_plan_py, write_plan_py
from cold_box_room.planning.paths import plan_py_path
from cold_box_room.room_a import formalize_plan_a, write_plan_a_md
from cold_box_room.testing.hallway import bootstrap_case_to_room2


@pytest.fixture
def plan_case(tmp_path, monkeypatch):
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

    case_id = "plan-py-roundtrip"
    d = staging / case_id
    d.mkdir(parents=True)
    (d / "disk.e01").write_bytes(b"E01")
    intake_case(case_id)
    bootstrap_case_to_room2(case_id)
    write_plan_a_md(
        case_id=case_id,
        markdown=f"""# Extraction plan — `{case_id}`

## Step 1 — Metadata

**Reason:** Chain of custody
""",
    )
    formalize_plan_a(case_id=case_id)
    return case_id


def test_extend_plan_writes_python_true_literal(plan_case):
    extend_plan_step(
        case_id=plan_case,
        room="a",
        title="Extra step",
        reason="Added during execution",
    )
    path = plan_py_path(plan_case, room="a")
    text = path.read_text(encoding="utf-8")
    assert "json.loads(" in text
    doc = load_plan_py(path, room="a")
    assert doc.steps[-1].proof.get("added_in_execution") is True


def test_forensic_strings_roundtrip(plan_case):
    path = plan_py_path(plan_case, room="a")
    doc = load_plan_py(path, room="a")
    doc.steps[0].status = "passed"
    doc.steps[0].proof = {
        "audit_id": "CB-test",
        "exit_code": 0,
        "note": (
            "Paths: C:\\Windows\\Prefetch\\*.pf, (SYSTEM\\Enum\\USBSTOR), "
            "[secret_project]_final.pptx.lnk, informant's 'informant-PC' — $MFT $I $R"
        ),
    }
    write_plan_py(path, doc, room="a")
    reloaded = load_plan_py(path, room="a")
    assert reloaded.steps[0].proof["note"] == doc.steps[0].proof["note"]


def test_parallel_apply_plan_status_is_atomic(plan_case):
    path = plan_py_path(plan_case, room="a")
    doc = load_plan_py(path, room="a")
    write_plan_a_md(
        case_id=plan_case,
        markdown=f"""# Extraction plan — `{plan_case}`

## Step 1 — One

**Reason:** First

## Step 2 — Two

**Reason:** Second
""",
    )
    formalize_plan_a(case_id=plan_case)

    def mark(step_id: int) -> None:
        apply_step_status(
            case_id=plan_case,
            room="a",
            step_id=step_id,
            status="passed",
            proof={
                "audit_id": f"CB-{step_id}",
                "exit_code": 0,
                "scratch_refs": [f"CB-{step_id}/stdout.txt"],
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(mark, (1, 2)))

    final = load_plan_py(path, room="a")
    assert final.steps[0].status == "passed"
    assert final.steps[1].status == "passed"


def test_write_plan_py_roundtrip(plan_case):
    path = plan_py_path(plan_case, room="a")
    doc = load_plan_py(path, room="a")
    write_plan_py(path, doc, room="a")
    reloaded = load_plan_py(path, room="a")
    assert reloaded.to_plan_dict() == doc.to_plan_dict()
