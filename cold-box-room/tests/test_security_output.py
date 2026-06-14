"""Output path harness — bulk_extractor and similar tools."""

from pathlib import Path

import pytest

from cold_box_room.r2.security import prepare_harness_output_args


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
