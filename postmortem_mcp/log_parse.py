"""Structured log parsers (JSONL / NDJSON)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SECURITY_HINTS = (
    "failed",
    "authentication",
    "logon",
    "4625",
    "4624",
    "attack",
    "exploit",
    "shell",
    "sql",
    "unauthorized",
    "denied",
)


def parse_structured_log(path: Path, *, max_records: int = 500) -> dict[str, Any]:
    """Parse JSONL/NDJSON logs and surface security-relevant events."""
    records: list[dict[str, Any]] = []
    flagged: list[dict[str, Any]] = []

    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError:
                row = {"raw_line": stripped, "line_no": line_no}
            if not isinstance(row, dict):
                row = {"value": row, "line_no": line_no}
            else:
                row.setdefault("line_no", line_no)
            records.append(row)

            blob = json.dumps(row, default=str).lower()
            if any(hint in blob for hint in SECURITY_HINTS):
                flagged.append(row)

            if len(records) >= max_records:
                break

    return {
        "source": str(path),
        "parser": "structured-log",
        "record_count": len(records),
        "records": records,
        "flagged_events": flagged,
        "flagged_count": len(flagged),
        "truncated": len(records) >= max_records,
    }
