"""Engine tests — extracted survey merge and path resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from postmortem_evidence.guard import resolve_read_path
from postmortem_mcp.survey import build_survey_payload, merge_extracted_survey


REPO = Path(__file__).resolve().parents[1]


def test_merge_extracted_survey_adds_evtx_and_mft(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extracted = tmp_path / "extracted"
    (extracted / "logs").mkdir(parents=True)
    (extracted / "logs" / "Security.evtx").write_bytes(b"evtx")
    (extracted / "$MFT").write_bytes(b"mft")

    base = build_survey_payload(tmp_path / "case", "case")
    merged = merge_extracted_survey(base, extracted)
    kinds = set(merged["kinds_present"])
    assert "evtx" in kinds
    assert "mft" in kinds
    rels = {f["relpath"] for f in merged["files"]}
    assert "extracted/logs/Security.evtx" in rels


def test_resolve_extracted_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    extracted = tmp_path / "disk"
    (extracted / "logs").mkdir(parents=True)
    evtx = extracted / "logs" / "Security.evtx"
    evtx.write_bytes(b"x")
    monkeypatch.setenv("EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setenv("EXTRACTED_ROOT", str(extracted))
    (tmp_path / "evidence").mkdir()
    resolved = resolve_read_path("extracted/logs/Security.evtx")
    assert resolved == evtx.resolve()
