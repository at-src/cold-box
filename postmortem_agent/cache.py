"""Replay cached tool JSON for fast demos on real cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def cache_path(cache_dir: Path, tool: str) -> Path:
    return cache_dir / f"{tool}.json"


def load_cached_tool(cache_dir: Path, tool: str) -> dict[str, Any] | None:
    path = cache_path(cache_dir, tool)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        inner = payload["data"]
        if "processes" in inner or "connections" in inner or "rows" in inner:
            return inner
    if isinstance(payload, dict) and "processes" in payload:
        return payload
    return payload if isinstance(payload, dict) else None
