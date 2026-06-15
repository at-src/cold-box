"""Tests for R1 evidence resolution and staging scope."""

from __future__ import annotations

import json

import pytest

from cold_box_room.e2e.accuracy import score_case_accuracy
from cold_box_room.r1.evidence import (
    expand_ewf_chain,
    list_directory_evidence,
    resolve_evidence_sources,
    validate_benchmark_staging_scope,
)
from cold_box_room.r1.intake import intake_case
from cold_box_room.r1.paths import StagingError


@pytest.fixture(autouse=True)
def _isolated_staging(tmp_path, monkeypatch):
    staging = tmp_path / "r1-staging"
    records = tmp_path / "records"
    staging.mkdir()
    records.mkdir()
    monkeypatch.setenv("COLD_BOX_R1_STAGING", str(staging))
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))
    monkeypatch.setenv("COLD_BOX_ROOM_STRICT", "0")


def test_expand_ewf_chain_from_e01(tmp_path):
    base = tmp_path / "case_pc"
    for name in ("case_pc.E01", "case_pc.E02", "case_pc.E03"):
        (tmp_path / name).write_bytes(b"x")
    chain = expand_ewf_chain(base.with_name("case_pc.E01"))
    assert [p.name for p in chain] == ["case_pc.E01", "case_pc.E02", "case_pc.E03"]


def test_expand_ewf_chain_non_e01_returns_single_file(tmp_path):
    path = tmp_path / "raw.dd"
    path.write_bytes(b"dd")
    assert expand_ewf_chain(path) == [path]


def test_resolve_directory_lists_all_files(tmp_path):
    (tmp_path / "a.E01").write_bytes(b"1")
    (tmp_path / "b.E01").write_bytes(b"2")
    names = [p.name for p in resolve_evidence_sources(tmp_path)]
    assert names == ["a.E01", "b.E01"]


def test_intake_symlinks_full_ewf_chain(tmp_path):
    src_dir = tmp_path / "evidence"
    src_dir.mkdir()
    for name in ("disk.E01", "disk.E02", "disk.E03"):
        (src_dir / name).write_bytes(b"seg")

    rec = intake_case("ewf-chain", source=src_dir / "disk.E01", link_only=True)
    staged = rec["staged_files"]
    assert staged == ["disk.E01", "disk.E02", "disk.E03"]


def test_intake_directory_stages_all_files(tmp_path):
    src_dir = tmp_path / "bundle"
    src_dir.mkdir()
    (src_dir / "one.E01").write_bytes(b"1")
    (src_dir / "two.E01").write_bytes(b"2")

    rec = intake_case("dir-intake", source=src_dir, link_only=True)
    assert sorted(rec["staged_files"]) == ["one.E01", "two.E01"]


def test_list_directory_evidence_rejects_empty(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(StagingError, match="No evidence files"):
        list_directory_evidence(empty)


def test_validate_benchmark_staging_scope():
    benchmark = {
        "required_staging_files": ["a.E01", "a.E02"],
        "optional_staging_files": ["b.E01"],
    }
    ok = validate_benchmark_staging_scope(staged_files={"a.E01", "a.E02", "b.E01"}, benchmark=benchmark)
    assert ok["scope_ok"] is True
    assert ok["missing_required"] == []

    bad = validate_benchmark_staging_scope(staged_files={"a.E01"}, benchmark=benchmark)
    assert bad["scope_ok"] is False
    assert bad["missing_required"] == ["a.E02"]


def test_score_marks_incomplete_staging_unscoped(monkeypatch, tmp_path):
    case_id = "ndlc-scope"
    records = tmp_path / "records" / case_id
    records.mkdir(parents=True)
    (records / "manifest.json").write_text(
        json.dumps({"files": [{"path": "cfreds_2015_data_leakage_pc.E01"}]}),
        encoding="utf-8",
    )
    (records / "layer1_analyst_log.md").write_text(
        "informant-pc windows 7 ntfs data leak a49d1254c873808c58e6f1bcd60b5bde\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("cold_box_room.e2e.accuracy.case_records_dir", lambda _cid: records)
    monkeypatch.setattr(
        "cold_box_room.e2e.accuracy.collect_case_report",
        lambda _cid: {"complete": True, "room": "3", "layer1": {}, "layer2": {}, "plans": {}},
    )
    monkeypatch.setattr(
        "cold_box_room.e2e.accuracy.audit_log_path",
        lambda _cid: records / "missing_audit.jsonl",
    )

    payload = score_case_accuracy(case_id=case_id, benchmark_id="ndlc_leakage_pc")
    assert payload["staging_scope_ok"] is False
    assert payload["accuracy_scoped"] is False
    assert payload["accuracy_pct"] is None
    assert payload["staging_scope"]["missing_required"]
