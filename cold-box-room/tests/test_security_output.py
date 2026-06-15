"""Output path harness — bulk_extractor and similar tools."""

from pathlib import Path

import pytest

from cold_box_room.r2.executor import _build_command, _split_sleuthkit_args
from cold_box_room.r2.security import prepare_harness_output_args, sanitize_extra_args
from cold_box_room.tools.registry import get_tool


def test_bulk_extractor_injects_scratch_o(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    out_dir = scratch / "CB-test_SIFT-032_bulk_extractor" / "output"
    out_dir.mkdir(parents=True)

    extra = prepare_harness_output_args(
        [],
        tool_name="bulk_extractor",
        output_style="scratch_dir_flag_o",
        output_dir=out_dir,
        scratch_root=scratch,
    )
    assert extra[:2] == ["-o", str(out_dir)]


def test_bulk_extractor_rewrites_tmp_o(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    out_dir = scratch / "run" / "output"
    out_dir.mkdir(parents=True)

    extra = prepare_harness_output_args(
        ["-o", "/tmp/be_output_m57jo"],
        tool_name="bulk_extractor",
        output_style="scratch_dir_flag_o",
        output_dir=out_dir,
        scratch_root=scratch,
    )
    assert extra[0] == "-o"
    assert extra[1] == str(out_dir)
    assert extra[1] != "/tmp/be_output_m57jo"
    assert Path(extra[1]).is_relative_to(scratch)


def test_tsk_fls_o_offset_not_rewritten(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    out_dir = scratch / "output"
    out_dir.mkdir()

    extra = prepare_harness_output_args(
        ["-o", "63", "-l", "23117"],
        tool_name="fls",
        output_style="stdout",
        output_dir=out_dir,
        scratch_root=scratch,
    )
    assert extra == ["-o", "63", "-l", "23117"]


def test_strings_allows_encoding_flag():
    args = sanitize_extra_args(["-e", "l", "-n", "5"], tool_name="strings")
    assert args == ["-e", "l", "-n", "5"]


def test_split_sleuthkit_args_fls_m_mount_before_image():
    flags, trailing = _split_sleuthkit_args(["-r", "-m", "/", "-o", "63"])
    assert flags == ["-r", "-m", "/", "-o", "63"]
    assert trailing == []


def test_build_command_fls_m_mount_before_image(tmp_path):
    image = tmp_path / "disk.E01"
    image.write_bytes(b"x")
    tool = get_tool("SIFT-148")
    cmd = _build_command(tool, image, ["-r", "-m", "/", "-o", "63"])
    assert cmd[-1] == str(image)
    assert cmd[1:] == ["-r", "-m", "/", "-o", "63", str(image)]


def test_build_command_grep_pattern_before_file(tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("cold-box-verify-token\n", encoding="utf-8")
    tool = get_tool("SIFT-010")
    cmd = _build_command(tool, target, ["-F", "cold-box-verify-token"])
    assert cmd[-1] == str(target)
    assert cmd[1:-1] == ["-F", "cold-box-verify-token"]
