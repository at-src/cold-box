"""Append-only progress.jsonl writer."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from postmortem_evidence.guard import assert_not_evidence_write


def progress_log_path(case_output_dir: Path) -> Path:
    path = case_output_dir / "progress.jsonl"
    assert_not_evidence_write(path, "a")
    return path


def utc_timestamp() -> str:
    now = time.time()
    whole, frac = divmod(now, 1)
    return time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime(whole)) + f"{int(frac * 1000):03d}Z"


def append_progress(
    path: Path,
    *,
    iteration: int,
    phase: str,
    hypothesis: str,
    confidence: float,
    unresolved: list[str],
    notes: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "iteration": iteration,
        "ts": utc_timestamp(),
        "phase": phase,
        "hypothesis": hypothesis,
        "confidence": confidence,
        "unresolved": list(unresolved),
        "notes": notes,
    }
    if extra:
        entry.update(extra)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return entry
