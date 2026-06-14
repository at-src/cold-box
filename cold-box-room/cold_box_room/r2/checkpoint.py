"""Layer 1 R2 checkpoint and promotion to room 3."""

from __future__ import annotations

import json
from typing import Any

from cold_box_room.r1.hallway import current_room, require_room
from cold_box_room.r1.paths import StagingError
from cold_box_room.r2.analyst_log import parse_analyst_log
from cold_box_room.r2.layer1_state import (
    MAX_PROMOTION_ATTEMPTS,
    load_layer1_state,
    record_layer1_exit,
    record_submission_attempt,
)
from cold_box_room.r2.logbook_paths import layer1_tool_log_md_path
from cold_box_room.r2.tool_log import iter_tool_log_entries, read_tool_log


class Layer1CheckpointError(StagingError):
    """Layer 1 promotion gate failed."""


def _is_successful_extraction(entry: dict[str, Any]) -> bool:
    if int(entry.get("exit_code", -1)) != 0:
        return False
    if entry.get("error"):
        return False
    scratch_refs = entry.get("scratch_refs") or []
    if scratch_refs:
        return True
    preview = str(entry.get("stdout_preview") or "").strip()
    return bool(preview)


def count_successful_extractions(case_id: str) -> int:
    return sum(1 for row in iter_tool_log_entries(case_id) if _is_successful_extraction(row))


def r2_layer1_checkpoint(case_id: str) -> dict[str, Any]:
    require_room(case_id, 2)
    state = load_layer1_state(case_id)
    analyst = parse_analyst_log(case_id)
    successful = count_successful_extractions(case_id)
    self_score = analyst["self_score"] if analyst else None

    extraction_gate = successful >= 1
    analyst_complete = bool(analyst and analyst.get("complete"))
    score_gate = self_score is not None and self_score > 8

    blocked: list[str] = []
    if state.get("exited"):
        blocked.append("layer1_exited")
    if not extraction_gate:
        blocked.append("no_successful_extraction")
    if not analyst_complete:
        blocked.append("analyst_log_incomplete")
    if analyst_complete and not score_gate:
        blocked.append("self_score_not_above_8")

    ready = extraction_gate and analyst_complete and score_gate and not state.get("exited")

    return {
        "case_id": case_id,
        "room": 2,
        "successful_extractions": successful,
        "extraction_gate": extraction_gate,
        "analyst_log": analyst,
        "self_score": self_score,
        "score_gate": score_gate,
        "promotion_attempts": int(state.get("promotion_attempts", 0)),
        "max_attempts": MAX_PROMOTION_ATTEMPTS,
        "attempts_remaining": max(
            0, MAX_PROMOTION_ATTEMPTS - int(state.get("promotion_attempts", 0))
        ),
        "exited": bool(state.get("exited")),
        "exit_reason": state.get("exit_reason") or "",
        "ready_for_room3": ready,
        "blocked_reasons": blocked,
        "tool_log_path": str(read_tool_log(case_id)["jsonl_path"]),
        "tool_logbook_path": str(layer1_tool_log_md_path(case_id)),
    }


def submit_layer1_writeup(
    *,
    case_id: str,
    findings: str,
    self_score: int,
    why: str,
) -> dict[str, Any]:
    from cold_box_room.r2.analyst_log import write_analyst_log

    require_room(case_id, 2)
    state = load_layer1_state(case_id)
    if state.get("exited"):
        return {
            "ok": False,
            "error": "Layer 1 already exited — cannot submit another write-up.",
            "checkpoint": r2_layer1_checkpoint(case_id),
        }

    write_info = write_analyst_log(
        case_id=case_id,
        findings=findings,
        self_score=self_score,
        why=why,
    )
    checkpoint = r2_layer1_checkpoint(case_id)

    if checkpoint["ready_for_room3"]:
        from cold_box_room.r1.hallway import promote_to_room3

        hallway = promote_to_room3(case_id)
        return {
            "ok": True,
            "promoted": True,
            "room": 3,
            "write_up": write_info,
            "checkpoint": checkpoint,
            "hallway": hallway,
        }

    state = record_submission_attempt(case_id, self_score=self_score)
    checkpoint = r2_layer1_checkpoint(case_id)
    checkpoint["promotion_attempts"] = state["promotion_attempts"]

    result: dict[str, Any] = {
        "ok": False,
        "promoted": False,
        "room": 2,
        "write_up": write_info,
        "checkpoint": checkpoint,
        "blocked_reasons": checkpoint["blocked_reasons"],
    }

    if int(state["promotion_attempts"]) >= MAX_PROMOTION_ATTEMPTS:
        result["attempts_exhausted"] = True
        result["hint"] = (
            "Three promotion attempts used. Call exit_layer1 with why you cannot score above 8."
        )
    else:
        result["attempts_exhausted"] = False
        result["hint"] = "Fix gaps and submit_layer1_writeup again, or run more tools first."

    return result


def exit_layer1(*, case_id: str, reason: str) -> dict[str, Any]:
    require_room(case_id, 2)
    state = load_layer1_state(case_id)
    if not reason.strip():
        raise Layer1CheckpointError("exit reason must not be empty")
    if int(state.get("promotion_attempts", 0)) < MAX_PROMOTION_ATTEMPTS:
        raise Layer1CheckpointError(
            f"exit_layer1 allowed only after {MAX_PROMOTION_ATTEMPTS} failed promotion attempts"
        )
    if state.get("exited"):
        return {
            "ok": True,
            "already_exited": True,
            "exit_reason": state.get("exit_reason"),
            "room": current_room(case_id),
        }

    updated = record_layer1_exit(case_id, reason)
    return {
        "ok": True,
        "exited": True,
        "room": 2,
        "exit_reason": updated["exit_reason"],
        "message": "Case ends in R2 — no Room 3.",
    }
