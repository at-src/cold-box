"""Room 1 — R1 staging area, seal, checkpoint."""

import pytest

from cold_box_room.r1.checkpoint import r1_checkpoint
from cold_box_room.r1.guard import TouchForbiddenError, assert_not_staging_write
from cold_box_room.r1.hallway import current_room, promote_to_room2
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import StagingError, case_staging_dir, resolve_in_staging
from cold_box_room.r1.seal import is_sealed
from cold_box_room.r1.staging_read import open_staging_read


@pytest.fixture(autouse=True)
def _isolated_staging(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    records = tmp_path / "records"
    staging.mkdir()
    records.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))


def test_intake_seals_and_starts_room1():
    staging = case_staging_dir("lab-1")
    staging.mkdir(parents=True)
    (staging / "sample.E01").write_bytes(b"raw-evidence-bytes")

    rec = intake_case("lab-1")
    assert rec["room"] == 1
    assert rec["status"] == "sealed"
    assert is_sealed("lab-1")
    assert current_room("lab-1") == 1


def test_r1_checkpoint_requires_non_empty_file():
    staging = case_staging_dir("lab-2")
    staging.mkdir(parents=True)
    (staging / "empty.bin").write_bytes(b"")
    (staging / "good.bin").write_bytes(b"x")
    intake_case("lab-2")

    check = r1_checkpoint("lab-2")
    assert check["ok"] is True
    assert "good.bin" in check["non_empty_files"]


def test_r1_checkpoint_fails_when_all_empty():
    staging = case_staging_dir("lab-3")
    staging.mkdir(parents=True)
    (staging / "zero.bin").write_bytes(b"")
    intake_case("lab-3")

    check = r1_checkpoint("lab-3")
    assert check["ok"] is False
    assert "all_files_empty" in check["reasons"]


def test_promote_to_room2_solid_wall():
    staging = case_staging_dir("lab-4")
    staging.mkdir(parents=True)
    (staging / "evidence.E01").write_bytes(b"evidence")
    intake_case("lab-4")

    promoted = promote_to_room2("lab-4")
    assert promoted["room"] == 2
    assert current_room("lab-4") == 2


def test_promote_blocked_when_checkpoint_fails():
    staging = case_staging_dir("lab-5")
    staging.mkdir(parents=True)
    (staging / "empty.bin").write_bytes(b"")
    intake_case("lab-5")

    with pytest.raises(StagingError, match="R1 checkpoint failed"):
        promote_to_room2("lab-5")


def test_write_blocked_after_seal():
    staging = case_staging_dir("lab-6")
    staging.mkdir(parents=True)
    (staging / "evidence.E01").write_bytes(b"evidence")
    intake_case("lab-6")

    target = staging / "evidence.E01"
    with pytest.raises((PermissionError, OSError)):
        target.write_bytes(b"tampered")

    with pytest.raises(TouchForbiddenError):
        assert_not_staging_write(target, "w")


def test_staging_read_only_after_seal():
    staging = case_staging_dir("lab-7")
    staging.mkdir(parents=True)
    (staging / "sample.bin").write_bytes(b"data")
    intake_case("lab-7")

    reader = open_staging_read("lab-7")
    assert reader.read_bytes("sample.bin") == b"data"
    assert "sample.bin" in [e.relpath for e in reader.list_dir(".")]


def test_direct_path_blocked_after_seal():
    staging = case_staging_dir("lab-8")
    staging.mkdir(parents=True)
    (staging / "x").write_bytes(b"1")
    intake_case("lab-8")

    with pytest.raises(TouchForbiddenError):
        resolve_in_staging("lab-8", "x")
