"""Room 1 — staging table, glass seal, checkpoint."""

import pytest

from cold_box_room.r1.checkpoint import r1_checkpoint
from cold_box_room.r1.guard import TouchForbiddenError, assert_not_table_write
from cold_box_room.r1.hallway import current_room, promote_to_room2
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import TableError, case_slot, resolve_on_table
from cold_box_room.r1.seal import is_sealed
from cold_box_room.r1.viewport import open_viewport


@pytest.fixture(autouse=True)
def _isolated_table(tmp_path, monkeypatch):
    table = tmp_path / "operation-table"
    records = tmp_path / "records"
    table.mkdir()
    records.mkdir()
    monkeypatch.setenv("COLD_BOX_ROOM_TABLE", str(table))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))


def test_intake_seals_and_starts_room1():
    slot = case_slot("lab-1")
    slot.mkdir(parents=True)
    (slot / "sample.E01").write_bytes(b"raw-evidence-bytes")

    rec = intake_case("lab-1")
    assert rec["room"] == 1
    assert rec["status"] == "sealed_on_table"
    assert is_sealed("lab-1")
    assert current_room("lab-1") == 1


def test_r1_checkpoint_requires_non_empty_file():
    slot = case_slot("lab-2")
    slot.mkdir(parents=True)
    (slot / "empty.bin").write_bytes(b"")
    (slot / "good.bin").write_bytes(b"x")
    intake_case("lab-2")

    check = r1_checkpoint("lab-2")
    assert check["ok"] is True
    assert "good.bin" in check["non_empty_files"]


def test_r1_checkpoint_fails_when_all_empty():
    slot = case_slot("lab-3")
    slot.mkdir(parents=True)
    (slot / "zero.bin").write_bytes(b"")
    intake_case("lab-3")

    check = r1_checkpoint("lab-3")
    assert check["ok"] is False
    assert "all_files_empty" in check["reasons"]


def test_promote_to_room2_solid_wall():
    slot = case_slot("lab-4")
    slot.mkdir(parents=True)
    (slot / "body.E01").write_bytes(b"evidence")
    intake_case("lab-4")

    promoted = promote_to_room2("lab-4")
    assert promoted["room"] == 2
    assert current_room("lab-4") == 2


def test_promote_blocked_when_checkpoint_fails():
    slot = case_slot("lab-5")
    slot.mkdir(parents=True)
    (slot / "empty.bin").write_bytes(b"")
    intake_case("lab-5")

    with pytest.raises(TableError, match="R1 checkpoint failed"):
        promote_to_room2("lab-5")


def test_write_blocked_after_seal():
    slot = case_slot("lab-6")
    slot.mkdir(parents=True)
    (slot / "body.E01").write_bytes(b"evidence")
    intake_case("lab-6")

    target = slot / "body.E01"
    with pytest.raises((PermissionError, OSError)):
        target.write_bytes(b"tampered")

    with pytest.raises(TouchForbiddenError):
        assert_not_table_write(target, "w")


def test_viewport_only_after_seal():
    slot = case_slot("lab-7")
    slot.mkdir(parents=True)
    (slot / "prize.bin").write_bytes(b"claw")
    intake_case("lab-7")

    vp = open_viewport("lab-7")
    assert vp.read_bytes("prize.bin") == b"claw"
    assert "prize.bin" in [e.relpath for e in vp.list_dir(".")]


def test_direct_path_blocked_after_seal():
    slot = case_slot("lab-8")
    slot.mkdir(parents=True)
    (slot / "x").write_bytes(b"1")
    intake_case("lab-8")

    with pytest.raises(TouchForbiddenError):
        resolve_on_table("lab-8", "x")
