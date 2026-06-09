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
    if isinstance(payload, dict) and "data" in payload:
        return payload
    return {"ok": True, "data": payload, "source": f"cache:{path}"}
