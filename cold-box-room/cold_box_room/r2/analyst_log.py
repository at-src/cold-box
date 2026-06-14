"""Layer 1 analyst log — agent-only write-up."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from cold_box_room.r1.hallway import require_room
from cold_box_room.r1.paths import StagingError
from cold_box_room.r2.logbook_paths import (
    ANALYST_LOG_HEADING,
    layer1_analyst_log_md_path,
)


class AnalystLogError(StagingError):
    """Invalid analyst log submission."""


def _validate_submission(*, findings: str, self_score: int, why: str) -> None:
    if not findings.strip():
        raise AnalystLogError("findings must not be empty")
    if not why.strip():
        raise AnalystLogError("why must not be empty")
    if not isinstance(self_score, int) or self_score < 1 or self_score > 10:
        raise AnalystLogError("self_score must be an integer from 1 to 10")


def format_analyst_log(*, findings: str, self_score: int, why: str) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    return (
        f"{ANALYST_LOG_HEADING}\n\n"
        f"_Agent write-up. Harness never appends tool rows here._\n\n"
        f"## Findings\n\n{findings.strip()}\n\n"
        f"## Self-score\n\n{self_score}\n\n"
        f"## Why\n\n{why.strip()}\n\n"
        f"_Submitted at {ts}_\n"
    )


def write_analyst_log(
    *,
    case_id: str,
    findings: str,
    self_score: int,
    why: str,
) -> dict[str, Any]:
    require_room(case_id, 2)
    _validate_submission(findings=findings, self_score=self_score, why=why)
    path = layer1_analyst_log_md_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        format_analyst_log(findings=findings, self_score=self_score, why=why),
        encoding="utf-8",
    )
    return {
        "path": str(path.resolve()),
        "self_score": self_score,
        "findings_chars": len(findings.strip()),
        "why_chars": len(why.strip()),
    }


def parse_analyst_log(case_id: str) -> dict[str, Any] | None:
    path = layer1_analyst_log_md_path(case_id)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")

    findings_match = re.search(
        r"## Findings\s*\n+(.*?)(?=\n## Self-score\s|\Z)",
        text,
        re.DOTALL,
    )
    score_match = re.search(r"## Self-score\s*\n+\s*(\d+)\s*", text)
    why_match = re.search(
        r"## Why\s*\n+(.*?)(?=\n_|\\Z)",
        text,
        re.DOTALL,
    )

    findings = findings_match.group(1).strip() if findings_match else ""
    why = why_match.group(1).strip() if why_match else ""
    self_score: int | None = None
    if score_match:
        self_score = int(score_match.group(1))

    complete = bool(findings and why and self_score is not None)
    return {
        "findings": findings,
        "self_score": self_score,
        "why": why,
        "complete": complete,
        "has_findings": bool(findings),
        "has_why": bool(why),
        "has_score": self_score is not None,
    }


def read_analyst_log(case_id: str) -> dict[str, Any]:
    path = layer1_analyst_log_md_path(case_id)
    if not path.is_file():
        return {"exists": False, "path": str(path), "content": "", "parsed": None}
    content = path.read_text(encoding="utf-8")
    return {
        "exists": True,
        "path": str(path.resolve()),
        "content": content,
        "parsed": parse_analyst_log(case_id),
    }
