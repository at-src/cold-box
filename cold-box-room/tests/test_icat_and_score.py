"""icat size parsing and analyst score normalization."""

import pytest

from cold_box_room.r2.analyst_log import normalize_self_score
from cold_box_room.r2.executor import _istat_size_bytes
from cold_box_room.r2.output_files import scratch_dir


PATENTAUTO_ISTAT = """
MFT Entry Header Values:
Entry: 24128        Sequence: 16
Allocated File

$FILE_NAME Attribute Values:
Flags: Archive
Name: patentauto.py
Allocated Size: 0   Actual Size: 0

Attributes:
Type: $DATA (128-4)   Name: N/A   Non-Resident   size: 3674  init_size: 3674
2849068
"""


def test_istat_size_ignores_allocated_size_zero(monkeypatch, tmp_path):
    image = tmp_path / "disk.e01"
    image.write_bytes(b"x")

    def fake_run(cmd, **kwargs):
        class Result:
            returncode = 0
            stdout = PATENTAUTO_ISTAT

        return Result()

    monkeypatch.setattr("cold_box_room.r2.executor.subprocess.run", fake_run)
    monkeypatch.setattr("cold_box_room.r2.executor.shutil.which", lambda _: "/usr/bin/istat")

    assert _istat_size_bytes(image, "63", "24128") == 3674


def test_normalize_self_score_percentage():
    assert normalize_self_score(72) == 7
    assert normalize_self_score(9) == 9
    assert normalize_self_score("8") == 8


def test_normalize_self_score_rejects_invalid():
    with pytest.raises(Exception):
        normalize_self_score(0)


def test_sqlite3_command_puts_db_before_args(monkeypatch, tmp_path):
    from cold_box_room.testing import bootstrap_case_to_room2
    from cold_box_room.r1.intake import intake_case
    from cold_box_room.r1.paths import case_staging_dir
    from cold_box_room.r2.scratch_analysis import run_scratch_analysis

    staging_root = tmp_path / "r1-staging"
    sandbox_root = tmp_path / "r2-sandbox"
    records_root = tmp_path / "records"
    for path in (staging_root, sandbox_root, records_root):
        path.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging_root))
    monkeypatch.setenv("COLD_BOX_R2_SANDBOX", str(sandbox_root))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records_root))

    staging = case_staging_dir("sqlite-cmd")
    staging.mkdir(parents=True)
    (staging / "x").write_bytes(b"x")
    intake_case("sqlite-cmd")
    bootstrap_case_to_room2("sqlite-cmd")

    db = scratch_dir("sqlite-cmd") / "test.db"
    db.write_bytes(b"x")
    captured: list[list[str]] = []

    class FakeProc:
        returncode = 0

        def __init__(self):
            self.stdout = self
            self.stderr = type("E", (), {"read": lambda self: b""})()

        def read(self, n=-1):
            return b"ok\n"

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

        def kill(self):
            return None

    def fake_popen(cmd, **kwargs):
        captured.append(list(cmd))
        return FakeProc()

    monkeypatch.setattr("cold_box_room.r2.scratch_analysis.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "cold_box_room.r2.scratch_analysis.stream_pipe_to_file",
        lambda pipe, out_path, **kwargs: (3, False),
    )
    monkeypatch.setattr("cold_box_room.r2.output_files.count_lines", lambda path: 1)
    monkeypatch.setattr("cold_box_room.r2.scratch_analysis.shutil.which", lambda _: "/usr/bin/sqlite3")

    run_scratch_analysis(
        case_id="sqlite-cmd",
        binary="sqlite3",
        scratch_relpath="test.db",
        purpose="t",
        why="t",
        args=[".tables"],
    )
    assert captured
    assert captured[0][1].endswith("test.db")
    assert captured[0][2] == ".tables"
