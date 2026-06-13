"""Load and query the SIFT tool catalog."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

from cold_box_room.tools.models import ToolRecord

MANIFEST_ENV = "COLD_BOX_TOOLS_MANIFEST"


class ToolCatalogError(ValueError):
    pass


def manifest_path() -> Path:
    raw = os.environ.get(MANIFEST_ENV, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "tools" / "manifest.json"


def load_manifest(*, path: Path | None = None) -> dict:
    mp = path or manifest_path()
    if not mp.is_file():
        raise ToolCatalogError(f"Tool manifest not found: {mp}")
    data = json.loads(mp.read_text(encoding="utf-8"))
    if data.get("schema") != "cold_box_room.tools_manifest_v1":
        raise ToolCatalogError(f"Unsupported manifest schema in {mp}")
    tools = data.get("tools") or []
    if int(data.get("count", -1)) != len(tools):
        raise ToolCatalogError(
            f"Manifest count mismatch in {mp}: count={data.get('count')} tools={len(tools)}"
        )
    return data


def clear_registry_cache() -> None:
    _records_by_id.cache_clear()


@lru_cache(maxsize=1)
def _records_by_id() -> dict[str, ToolRecord]:
    records: dict[str, ToolRecord] = {}
    for raw in load_manifest().get("tools", []):
        rec = ToolRecord.from_dict(raw)
        if rec.tool_id in records:
            raise ToolCatalogError(f"Duplicate tool_id {rec.tool_id!r}")
        records[rec.tool_id] = rec
    return records


def get_tool(tool_id: str) -> ToolRecord:
    key = tool_id.strip().upper()
    try:
        return _records_by_id()[key]
    except KeyError as exc:
        raise ToolCatalogError(f"Unknown tool_id {tool_id!r}") from exc


def list_tools(
    *,
    category: str | None = None,
    runnable_only: bool = False,
) -> list[ToolRecord]:
    rows = list(_records_by_id().values())
    if category:
        rows = [r for r in rows if r.category == category]
    if runnable_only:
        rows = [r for r in rows if r.verification.agent_runnable]
    return sorted(rows, key=lambda r: r.tool_id)


def list_categories() -> list[str]:
    return sorted({r.category for r in _records_by_id().values()})


def list_tools_dict(
    *,
    category: str | None = None,
    runnable_only: bool = False,
) -> list[dict]:
    return [t.to_list_dict() for t in list_tools(category=category, runnable_only=runnable_only)]


def describe_tool(tool_id: str) -> dict:
    return get_tool(tool_id).to_describe_dict()
