"""Mactime bodyfile validation."""

import pytest

from cold_box_room.r2.mactime_utils import (
    MactimeBodyfileError,
    is_valid_tsk_bodyfile,
    validate_mactime_bodyfile,
)


def test_rejects_disk_image_suffix(tmp_path):
    image = tmp_path / "disk.E01"
    image.write_bytes(b"x" * 100)
    with pytest.raises(MactimeBodyfileError, match="disk image"):
        validate_mactime_bodyfile(image)


def test_accepts_pipe_bodyfile(tmp_path):
    body = tmp_path / "bodyfile.txt"
    body.write_text("0|root|/|d|0|0|0|0\n", encoding="utf-8")
    validate_mactime_bodyfile(body)
    assert is_valid_tsk_bodyfile(body)


def test_rejects_non_pipe_file(tmp_path):
    bad = tmp_path / "fls_human.txt"
    bad.write_text("r/r 5: Documents and Settings\n", encoding="utf-8")
    with pytest.raises(MactimeBodyfileError, match="pipe-delimited"):
        validate_mactime_bodyfile(bad)
