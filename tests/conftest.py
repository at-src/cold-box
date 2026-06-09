"""Shared pytest configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _default_evidence_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tests never depend on a stale host EVIDENCE_ROOT."""
    monkeypatch.setenv("EVIDENCE_ROOT", str(REPO_ROOT / "examples" / "sample-evidence"))
