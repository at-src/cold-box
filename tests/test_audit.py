"""Tests for Step 2 — audit log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from postmortem_audit import AuditLog, verify_chain


def test_write_three_entries_read_back(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)

    ids: list[str] = []
    for i in range(3):
        audit_id = log.append(
            tool=f"tool_{i}",
            args={"case": "sample", "step": i},
            result={"ok": True, "count": i},
            iteration=i,
        )
        ids.append(audit_id)

    entries = log.read_entries()
    assert len(entries) == 3
    assert [entry["audit_id"] for entry in entries] == ids
    assert entries[0]["tool"] == "tool_0"
    assert entries[2]["iteration"] == 2
    assert entries[1]["result_digest"].startswith("sha256:")


def test_verify_chain_ok(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    for i in range(3):
        log.append("evidence_manifest", {"path": "sample"}, {"files": i}, iteration=0)

    ok, message = verify_chain(log_path)
    assert ok is True
    assert "3 entries" in message


def test_verify_detects_tampering(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    for i in range(3):
        log.append("tool", {"i": i}, {"n": i}, iteration=0)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["args"] = {"i": 999}
    lines[1] = json.dumps(obj, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, message = verify_chain(log_path)
    assert ok is False
    assert "entry_hash mismatch" in message


def test_resume_appends_to_existing_chain(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    AuditLog(log_path).append("a", {}, {"v": 1}, iteration=1)
    AuditLog(log_path).append("b", {}, {"v": 2}, iteration=2)

    ok, message = verify_chain(log_path)
    assert ok is True
    assert "2 entries" in message


def test_lookup_by_audit_id(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    first = log.append("one", {}, {"v": 1}, iteration=0)
    log.append("two", {}, {"v": 2}, iteration=0)

    found = log.lookup(first)
    assert found is not None
    assert found["tool"] == "one"
    assert log.lookup("deadbeef") is None


def test_append_only_file_mode(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.append("tool", {"x": 1}, {"y": 2}, iteration=0)

    with log_path.open("r", encoding="utf-8") as handle:
        first_line = handle.readline()
    assert first_line.endswith("\n")
    assert "audit_id" in json.loads(first_line)
