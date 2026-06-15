"""Tests for E2E accuracy scoring."""

from __future__ import annotations

from cold_box_room.e2e.accuracy import load_benchmark, score_case_accuracy


def test_terry_benchmark_loads():
    spec = load_benchmark("terry_usb")
    assert spec["id"] == "terry_usb"
    assert len(spec["checks"]) >= 4


def test_score_case_accuracy_on_fixture_case(monkeypatch, tmp_path):
    case_id = "acc-test"
    records = tmp_path / "records" / case_id
    records.mkdir(parents=True)
    (records / "layer1_analyst_log.md").write_text(
        "FAT32 TERRYS WORK keylogger R54402 ewf E01\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "cold_box_room.e2e.accuracy.case_records_dir",
        lambda _cid: records,
    )
    monkeypatch.setattr(
        "cold_box_room.e2e.accuracy.collect_case_report",
        lambda _cid: {
            "complete": True,
            "room": "3",
            "layer1": {"findings": "Advanced Keylogger on FAT32", "self_score": 9},
            "layer2": {"findings": "R54402.EXE", "self_score": 9},
            "plans": {},
        },
    )
    monkeypatch.setattr(
        "cold_box_room.e2e.accuracy.audit_log_path",
        lambda _cid: records / "missing_audit.jsonl",
    )

    payload = score_case_accuracy(case_id=case_id, benchmark_id="terry_usb", run_id="acc-test")
    assert payload["required_recall_pct"] == 100.0
    assert payload["complete"] is True
