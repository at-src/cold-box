"""Agent situation briefing — R1 pass context for opening message."""

from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.hallway import current_room
from cold_box_room.testing import bootstrap_case_to_room2
from cold_box_room.r1.paths import case_staging_dir
from cold_box_room.agent.situation import format_case_situation_briefing


def test_briefing_includes_r1_pass_reason_and_sandbox_files(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    sandbox = tmp_path / "r2-sandbox"
    records = tmp_path / "records"
    for path in (staging, sandbox, records):
        path.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(sandbox))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))

    case_id = "brief-a"
    d = case_staging_dir(case_id)
    d.mkdir(parents=True)
    (d / "fake-disk.e01").write_bytes(b"NOT-EMPTY-EVIDENCE")
    intake_case(case_id)
    bootstrap_case_to_room2(case_id)

    text = format_case_situation_briefing(case_id)
    assert current_room(case_id) == "2"
    assert "Room 1" in text
    assert "Room A" in text
    assert "fake-disk.e01" in text
    assert "sealed" in text.lower() or "non-empty" in text.lower()
    assert "R2 sandbox" in text or "sandbox" in text.lower()
    assert "ready_for_room_b" in text
    assert "no_successful_extraction" in text or "Blocked:" in text


def test_briefing_lists_r2_gate_criteria(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    sandbox = tmp_path / "r2-sandbox"
    records = tmp_path / "records"
    for path in (staging, sandbox, records):
        path.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(sandbox))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))

    case_id = "brief-b"
    d = case_staging_dir(case_id)
    d.mkdir(parents=True)
    (d / "x.bin").write_bytes(b"x")
    intake_case(case_id)
    bootstrap_case_to_room2(case_id)

    text = format_case_situation_briefing(case_id)
    assert "Room B pass criteria" in text
    assert "Self-score integer 1–10" in text or "1–10" in text
    assert "Successful extractions: 0" in text
