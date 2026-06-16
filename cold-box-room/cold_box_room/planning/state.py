"""Planning room session state — formalize timestamps."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r1.paths import case_records_dir


def _state_path(case_id: str, *, room: str) -> Path:
    return case_records_dir(case_id) / f"room_{room.lower()}_state.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_state(case_id: str, *, room: str) -> dict[str, Any]:
    path = _state_path(case_id, room=room)
    if not path.is_file():
        return {"case_id": case_id, "room": room.upper()}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(case_id: str, *, room: str, data: dict[str, Any]) -> None:
    path = _state_path(case_id, room=room)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def record_plan_formalized(case_id: str, *, room: str) -> dict[str, Any]:
    data = load_state(case_id, room=room)
    data["plan_formalized_at"] = _now()
    data["plan_formalize_count"] = int(data.get("plan_formalize_count", 0)) + 1
    save_state(case_id, room=room, data=data)
    return {"ok": True, "plan_formalized_at": data["plan_formalized_at"]}


def plan_was_formalized(case_id: str, *, room: str) -> bool:
    return bool(load_state(case_id, room=room).get("plan_formalized_at"))


def record_tools_catalog_browse(
    case_id: str,
    *,
    room: str,
    tool_name: str = "list_sift_tools",
) -> None:
    data = load_state(case_id, room=room)
    data["tools_catalog_browse_count"] = int(data.get("tools_catalog_browse_count", 0)) + 1
    events = list(data.get("events") or [])
    events.append({"ts": _now(), "event": "tools_catalog_browse", "tool_name": tool_name})
    data["events"] = events[-50:]
    save_state(case_id, room=room, data=data)
