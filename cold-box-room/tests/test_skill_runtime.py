"""Regression tests for skill runtime argument routing."""

from __future__ import annotations

import pytest

from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import case_staging_dir
from cold_box_room.r2.output_files import scratch_dir
from cold_box_room.skills.skill_runtime import SkillRuntime, SkillRuntimeError, activate, parse_and_run
from cold_box_room.testing.hallway import bootstrap_case_to_room3


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


def _bootstrap(case_id: str) -> SkillRuntime:
    staging = case_staging_dir(case_id)
    staging.mkdir(parents=True)
    (staging / "disk.E01").write_bytes(b"evidence")
    intake_case(case_id)
    bootstrap_case_to_room3(case_id)
    from cold_box_room.r2.paths import case_sandbox_dir

    sb = case_sandbox_dir(case_id)
    sb.mkdir(parents=True, exist_ok=True)
    (sb / "disk.E01").write_bytes(b"evidence")
    return SkillRuntime(
        case_id=case_id,
        journal_id="CB-SKL-TEST",
        skill_id="SKILL-TEST",
        input_relpath="disk.E01",
        evidence_abs_path=sb / "disk.E01",
    )


def test_scratch_relpath_does_not_strip_numeric_sleuthkit_args(monkeypatch):
    runtime = _bootstrap("skill-runtime-offset")
    scratch = scratch_dir(runtime.case_id)
    scratch.mkdir(parents=True, exist_ok=True)

    captured: list[list[str]] = []

    def fake_run_harness_tool(**kwargs):
        captured.append(list(kwargs.get("extra_args") or []))
        return {"audit_id": "CB-test", "exit_code": 0, "stdout_preview": "ok"}

    monkeypatch.setattr(
        "cold_box_room.skills.skill_runtime._run_harness_tool",
        fake_run_harness_tool,
    )

    with activate(runtime):
        parse_and_run(["icat", "-o", "63", str(runtime.evidence_abs_path), "0"])

    assert captured
    assert captured[0] == ["-o", "63", "0"]


def test_mactime_rejects_disk_image_as_bodyfile():
    runtime = _bootstrap("skill-runtime-mactime-block")
    with activate(runtime):
        with pytest.raises(SkillRuntimeError, match="bodyfile"):
            parse_and_run(["mactime", "-b", str(runtime.evidence_abs_path), "-d"])


def test_mactime_uses_scratch_bodyfile(tmp_path, monkeypatch):
    runtime = _bootstrap("skill-runtime-mactime-body")
    bodyfile = scratch_dir(runtime.case_id) / "bodyfile.txt"
    bodyfile.parent.mkdir(parents=True, exist_ok=True)
    bodyfile.write_text("0|root|/|d|0|0|0|0\n", encoding="utf-8")

    captured: dict = {}

    def fake_run_mactime(**kwargs):
        captured.update(kwargs)
        return {
            "audit_id": "CB-mactime",
            "exit_code": 0,
            "stdout_preview": "timeline",
        }

    monkeypatch.setattr(
        "cold_box_room.skills.skill_runtime._run_mactime_on_bodyfile",
        fake_run_mactime,
    )

    with activate(runtime):
        out, err, rc = parse_and_run(["mactime", "-b", str(bodyfile), "-d"])

    assert rc == 0
    assert out == "timeline"
    assert captured["bodyfile"] == bodyfile
