"""Skill harness execution in Room 3."""

import pytest

from cold_box_room.agent.tools import dispatch_tool
from cold_box_room.planning.guard import PlanningRoomGuardError, assert_tool_allowed_in_room
from cold_box_room.r1.hallway import current_room
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import case_staging_dir
from cold_box_room.room_3.skill_log import read_skill_log
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


def test_removed_reference_skill_not_in_catalog():
    case_id = "skill-ref-removed"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)

    result = run_skill(
        skill_id="SKILL-002",
        case_id=case_id,
        input_relpath="disk.E01",
    )
    assert result["ok"] is False
    assert "Unknown skill ref" in result["error"]


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


def test_run_skill_resolves_sandbox_in_room3_not_room2_error():
    """Regression: skill runner must not require Room 2 before harness activates."""
    case_id = "skill-room3-resolve"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    from cold_box_room.r2.paths import case_sandbox_dir
    from cold_box_room.r2.sandbox_input import resolve_sandbox_input_for_skill

    sb = case_sandbox_dir(case_id)
    sb.mkdir(parents=True, exist_ok=True)
    (sb / "disk.E01").write_bytes(b"evidence")
    assert current_room(case_id) == "3"
    path = resolve_sandbox_input_for_skill(case_id, "disk.E01")
    assert path.is_file()


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


def test_dispatch_list_sandbox_files_room3():
    case_id = "sandbox-dispatch-r3"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    _sandbox_e01(case_id)

    result = dispatch_tool("list_sandbox_files", {"case_id": case_id})
    assert result["ok"] is True
    assert result["r2_status_state"] == "available"
    assert result["r2_status"]["file_count"] >= 1


def test_dispatch_list_sandbox_files_blocked_in_room_a():
    case_id = "sandbox-dispatch-a"
    _intake(case_id)
    from cold_box_room.r1.hallway import promote_to_room_a

    promote_to_room_a(case_id)
    result = dispatch_tool("list_sandbox_files", {"case_id": case_id})
    assert result["ok"] is True
    assert result["outcome"] == "room_gated"
    assert "Room A" in result["error"]


def test_dispatch_list_skills_in_room_b():
    case_id = "skill-dispatch-b"
    _intake(case_id)
    from cold_box_room.testing.hallway import bootstrap_case_to_room_b

    bootstrap_case_to_room_b(case_id)
    result = dispatch_tool("list_skills", {"case_id": case_id})
    assert result["count"] == 171
    assert result["skills"][0]["skill_id"] == "SKILL-001"
    assert "has_script" in result["skills"][0]


def _sandbox_e01(case_id: str, payload: bytes = b"evidence") -> None:
    from cold_box_room.r2.paths import case_sandbox_dir

    sb = case_sandbox_dir(case_id)
    sb.mkdir(parents=True, exist_ok=True)
    (sb / "disk.E01").write_bytes(payload)


def test_skill_034_routes_sift_tools(case_id: str = "skill-034-harness"):
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    _sandbox_e01(case_id)

    result = run_skill(
        skill_id="SKILL-034",
        case_id=case_id,
        input_relpath="disk.E01",
        purpose="verify disk forensics skill harness",
        why="Regression: SKILL-034 must emit SIFT audit ids",
    )
    assert result["ok"] is True
    assert result["outcome"] in {"success", "failed"}
    if result["outcome"] == "success":
        assert len(result["audit_ids"]) >= 3


def test_skill_runner_rejects_scripts_without_entry_point(monkeypatch):
    from cold_box_room.skills import skill_runner

    case_id = "skill-no-entry"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    _sandbox_e01(case_id)

    slug = "_test_no_entry"
    script_dir = skill_runner.LIBRARY_DIR / slug / "scripts"
    script_dir.mkdir(parents=True, exist_ok=True)
    script = script_dir / "agent.py"
    script.write_text("# no entry point\nx = 1\n", encoding="utf-8")

    class FakeRow:
        skill_id = "SKILL-TEST"
        journal_id = "CB-SKL-TEST"
        library_slug = slug
        has_script = True
        reference_only = False

    import cold_box_room.skills.registry as reg

    monkeypatch.setattr(skill_runner, "resolve_skill_ref", lambda _ref: FakeRow())
    try:
        out = skill_runner.run_skill_script(
            case_id=case_id,
            skill_ref="SKILL-TEST",
            input_relpath="disk.E01",
        )
        assert out["ok"] is False
        assert "no harness entry point" in out["error"]
    finally:
        import shutil

        shutil.rmtree(skill_runner.LIBRARY_DIR / slug, ignore_errors=True)


def test_mft_skill_systemexit_is_contained(case_id: str = "skill-mft-harness"):
    from cold_box_room.skills import skill_runner

    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    _sandbox_e01(case_id)

    out = skill_runner.run_skill_script(
        case_id=case_id,
        skill_ref="SKILL-088",
        input_relpath="disk.E01",
    )
    assert isinstance(out, dict)
    assert out.get("ok") is False or out.get("audit_ids")


def test_all_skill_scripts_expose_analyze_image():
    from cold_box_room.skills.registry import LIBRARY_DIR

    missing = []
    for script in sorted(LIBRARY_DIR.glob("*/scripts/agent.py")):
        src = script.read_text(encoding="utf-8")
        if "def analyze_image" not in src:
            missing.append(script.parts[-3])
    assert missing == []


def test_sample_skills_emit_audit_ids():
    from cold_box_room.skills.registry import list_skills

    case_id = "skill-sample-audit"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    _sandbox_e01(case_id)

    samples = ["SKILL-034", "SKILL-074", "SKILL-088"]
    catalog = {row.skill_id for row in list_skills()}
    successes: list[str] = []
    for skill_id in samples:
        if skill_id not in catalog:
            continue
        result = run_skill(
            skill_id=skill_id,
            case_id=case_id,
            input_relpath="disk.E01",
            purpose="harness audit regression",
            why="bulk skill fix validation",
        )
        assert result["ok"] is True, skill_id
        assert result["outcome"] in {"success", "failed"}, skill_id
        if result["outcome"] == "success":
            assert result.get("audit_ids"), f"{skill_id}: {result.get('error')}"
            successes.append(skill_id)
    assert "SKILL-034" in successes


def test_run_skill_failed_attempt_still_runnable(monkeypatch):
    case_id = "skill-failed-retry"
    _intake(case_id)
    bootstrap_case_to_room3(case_id)
    _sandbox_e01(case_id)

    monkeypatch.setattr(
        "cold_box_room.skills.executor.run_skill_script",
        lambda **_: {
            "ok": False,
            "error": "icat failed",
            "audit_ids": [],
            "skill_id": "SKILL-088",
            "journal_id": "CB-SKL-088",
            "library_slug": "cb-mft-for-deleted-file-recovery",
        },
    )
    result = run_skill(
        skill_id="SKILL-088",
        case_id=case_id,
        input_relpath="disk.E01",
        purpose="test retry semantics",
        why="failed attempt should not look unavailable",
    )
    assert result["ok"] is True
    assert result["outcome"] == "failed"
    assert result["runnable"] is True
    assert result["retryable"] is True
    log = read_skill_log(case_id)
    assert log["by_skill"]["SKILL-088"]["failures"] == 1
    assert log["by_skill"]["SKILL-088"]["runnable"] is True
