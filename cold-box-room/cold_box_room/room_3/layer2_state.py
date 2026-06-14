"""Layer 2 promotion attempt tracking."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cold_box_room.room_3.logbook_paths import MAX_PROMOTION_ATTEMPTS, layer2_state_path


def load_layer2_state(case_id: str) -> dict[str, Any]:
    path = layer2_state_path(case_id)
    if not path.is_file():
        return {
            "promotion_attempts": 0,
            "complete": False,
            "complete_reason": "",
            "exited": False,
            "exit_reason": "",
            "last_submission_at": None,
        }
    return json.loads(path.read_text(encoding="utf-8"))


def save_layer2_state(case_id: str, state: dict[str, Any]) -> None:
    path = layer2_state_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def record_submission_attempt(case_id: str, *, self_score: int) -> dict[str, Any]:
    state = load_layer2_state(case_id)
    state["promotion_attempts"] = int(state.get("promotion_attempts", 0)) + 1
    state["last_submission_at"] = datetime.now(timezone.utc).isoformat()
    state["last_self_score"] = self_score
    save_layer2_state(case_id, state)
    return state


def record_layer2_complete(case_id: str, *, reason: str = "") -> dict[str, Any]:
    state = load_layer2_state(case_id)
    state["complete"] = True
    state["complete_reason"] = reason.strip()
    state["completed_at"] = datetime.now(timezone.utc).isoformat()
    save_layer2_state(case_id, state)
    return state


def record_layer2_exit(case_id: str, reason: str) -> dict[str, Any]:
    state = load_layer2_state(case_id)
    state["exited"] = True
    state["exit_reason"] = reason.strip()
    state["exited_at"] = datetime.now(timezone.utc).isoformat()
    save_layer2_state(case_id, state)
    return state
