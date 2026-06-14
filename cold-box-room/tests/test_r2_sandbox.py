"""Room 2 — sandbox materialization on R1 promotion."""

import pytest

from cold_box_room.r1.hallway import current_room, require_room
from cold_box_room.testing import bootstrap_case_to_room2
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import StagingError, case_staging_dir
from cold_box_room.r2.paths import case_sandbox_dir
from cold_box_room.r2.sandbox import list_sandbox_files, materialize_sandbox, r2_status


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


def test_promotion_materializes_sandbox_copy():
    staging = case_staging_dir("case-a")
    staging.mkdir(parents=True)
    (staging / "disk.E01").write_bytes(b"raw-evidence")
    intake_case("case-a")

    bootstrap_case_to_room2("case-a")
    sandbox = case_sandbox_dir("case-a")
    copied = sandbox / "disk.E01"

    assert current_room("case-a") == "2"
    assert copied.is_file()
    assert copied.read_bytes() == b"raw-evidence"
    assert list_sandbox_files("case-a") == [{"path": "disk.E01", "size": 12}]


def test_r1_staging_stays_sealed_after_r2_promotion():
    staging = case_staging_dir("case-b")
    staging.mkdir(parents=True)
    original = staging / "sample.bin"
    original.write_bytes(b"sealed-original")
    intake_case("case-b")
    bootstrap_case_to_room2("case-b")

    sandbox_file = case_sandbox_dir("case-b") / "sample.bin"
    sandbox_file.write_bytes(b"touched-in-sandbox")

    assert original.read_bytes() == b"sealed-original"
    assert sandbox_file.read_bytes() == b"touched-in-sandbox"


def test_r2_status_requires_room2():
    staging = case_staging_dir("case-c")
    staging.mkdir(parents=True)
    (staging / "x").write_bytes(b"1")
    intake_case("case-c")

    with pytest.raises(StagingError, match="required room 2"):
        r2_status("case-c")


def test_materialize_without_promotion_record():
    staging = case_staging_dir("case-d")
    staging.mkdir(parents=True)
    (staging / "y").write_bytes(b"2")
    intake_case("case-d")

    record = materialize_sandbox("case-d")
    assert record["file_count"] == 1
    assert case_sandbox_dir("case-d").is_dir()


def test_r2_status_after_promotion():
    staging = case_staging_dir("case-e")
    staging.mkdir(parents=True)
    (staging / "a.bin").write_bytes(b"abc")
    (staging / "empty.bin").write_bytes(b"")
    intake_case("case-e")
    bootstrap_case_to_room2("case-e")

    status = r2_status("case-e")
    assert status["room"] == "2"
    assert status["file_count"] == 2
    assert status["non_empty_files"] == ["a.bin"]
    require_room("case-e", 2)


def test_promotion_with_symlink_intake(tmp_path, monkeypatch):
    external = tmp_path / "external.E01"
    external.write_bytes(b"linked-evidence")
    monkeypatch.setenv("COLD_BOX_ROOM_STRICT", "0")

    staging = case_staging_dir("case-symlink")
    staging.mkdir(parents=True)
    intake_case("case-symlink", source=external, link_only=True)
    bootstrap_case_to_room2("case-symlink")

    sandbox_file = case_sandbox_dir("case-symlink") / "external.E01"
    assert sandbox_file.is_file() or sandbox_file.is_symlink()
    assert sandbox_file.read_bytes() == b"linked-evidence"


def test_sandbox_input_accepts_symlinked_evidence(tmp_path, monkeypatch):
    external = tmp_path / "big.E01"
    external.write_bytes(b"disk-bytes")
    monkeypatch.setenv("COLD_BOX_ROOM_STRICT", "0")

    staging = case_staging_dir("case-resolve")
    staging.mkdir(parents=True)
    intake_case("case-resolve", source=external, link_only=True)
    bootstrap_case_to_room2("case-resolve")

    from cold_box_room.r2.sandbox_input import resolve_sandbox_input

    path = resolve_sandbox_input("case-resolve", "big.E01")
    assert path.read_bytes() == b"disk-bytes"
