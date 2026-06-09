"""Tests for Step 1 — evidence layer."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from postmortem_evidence.guard import EvidencePathError, assert_not_evidence_write, resolve_read_path
from postmortem_evidence.integrity import IntegritySession
from postmortem_evidence.manifest import build_manifest, manifest_digest, sha256_file


@pytest.fixture
def evidence_tree(tmp_path, monkeypatch):
    root = tmp_path / "evidence"
    case = root / "case-a"
    (case / "disk").mkdir(parents=True)
    (case / "memory").mkdir(parents=True)
    (case / "disk" / "a.txt").write_text("disk-a\n", encoding="utf-8")
    (case / "memory" / "b.txt").write_text("mem-b\n", encoding="utf-8")
    monkeypatch.setenv("EVIDENCE_ROOT", str(root))
    return root, case


def test_sha256_file_stable(evidence_tree):
    _, case = evidence_tree
    path = case / "disk" / "a.txt"
    assert sha256_file(path) == sha256_file(path)
    assert len(sha256_file(path)) == 64


def test_build_manifest_lists_all_files(evidence_tree):
    _, case = evidence_tree
    manifest = build_manifest(case)
    assert manifest["file_count"] == 2
    paths = {item["path"] for item in manifest["files"]}
    assert paths == {"disk/a.txt", "memory/b.txt"}


def test_resolve_read_path_rejects_outside_root(evidence_tree, tmp_path):
    root, case = evidence_tree
    inside = resolve_read_path(case, evidence_root=root)
    assert inside == case.resolve()

    outside = tmp_path / "other.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(EvidencePathError):
        resolve_read_path(outside, evidence_root=root)


def test_write_guard_blocks_evidence_root(evidence_tree):
    root, _ = evidence_tree
    target = root / "tamper.txt"
    with pytest.raises(EvidencePathError):
        assert_not_evidence_write(target, "w")
    assert_not_evidence_write("/tmp/safe.txt", "w")


def test_integrity_session_intact(evidence_tree):
    _, case = evidence_tree
    session = IntegritySession(case_root=case)
    session.begin()
    result = session.check()
    assert result["intact"] is True
    assert result["changed"] == []


def test_integrity_session_detects_change(evidence_tree):
    _, case = evidence_tree
    session = IntegritySession(case_root=case)
    session.begin()
    (case / "disk" / "a.txt").write_text("modified\n", encoding="utf-8")
    result = session.check()
    assert result["intact"] is False
    assert "disk/a.txt" in result["changed"]


def test_integrity_baseline_save_load(evidence_tree, tmp_path):
    _, case = evidence_tree
    session = IntegritySession(case_root=case)
    session.begin()
    baseline_path = tmp_path / "baseline.json"
    session.save_baseline(baseline_path)

    loaded = IntegritySession.load_baseline(case, baseline_path)
    result = loaded.check()
    assert result["intact"] is True


def test_sample_evidence_in_repo():
    repo_root = Path(__file__).resolve().parents[1]
    sample = repo_root / "examples" / "sample-evidence"
    assert sample.is_dir()
    manifest = build_manifest(sample, evidence_root=sample)
    assert manifest["file_count"] >= 2
    assert manifest_digest(manifest) == manifest_digest(manifest)
