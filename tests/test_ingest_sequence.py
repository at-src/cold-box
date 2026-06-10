"""Ingest-first orchestration: a raw disk image must be extracted before analysis.

These cover the deterministic decision in ``_extract_first_action`` that runs in
the agent loop *before* either reasoner gets a turn, so the ingest-first sequence
is an architectural guarantee rather than a prompt the LLM could skip.
"""

from __future__ import annotations

from pathlib import Path

from postmortem_agent.core import _call_key, _extract_first_action
from postmortem_agent.state import AgentConfig


def _config() -> AgentConfig:
    return AgentConfig(case_id="seq", evidence_case=".", mode="autonomous")


_DISK_SURVEY = {
    "files": [
        {"relpath": "notes.txt", "kind": "text"},
        {"relpath": "images/disk.E01", "kind": "disk_image"},
    ]
}


def test_forces_extraction_when_unprocessed_image_present() -> None:
    action = _extract_first_action(_DISK_SURVEY, _config(), set(), {})
    assert action is not None
    assert action["tool"] == "disk_extract_image"
    assert action["arguments"] == {"image_relpath": "images/disk.E01"}


def test_no_extraction_once_already_run() -> None:
    action = _extract_first_action(_DISK_SURVEY, _config(), {"disk_extract_image"}, {})
    assert action is None


def test_no_extraction_when_image_extraction_failed() -> None:
    # A failed extraction must not loop forever — the agent degrades gracefully.
    failed = {_call_key("disk_extract_image", {"image_relpath": "images/disk.E01"}): "no tsk"}
    action = _extract_first_action(_DISK_SURVEY, _config(), set(), failed)
    assert action is None


def test_no_extraction_without_disk_image() -> None:
    survey = {"files": [{"relpath": "mem.raw", "kind": "memory_image"}]}
    assert _extract_first_action(survey, _config(), set(), {}) is None


def test_skips_when_extracted_root_already_provided(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    config = AgentConfig(
        case_id="seq",
        evidence_case=".",
        mode="autonomous",
        extracted_root=extracted,
    )
    assert _extract_first_action(_DISK_SURVEY, config, set(), {}) is None
