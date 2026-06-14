"""Room 3 Layer 2 checkpoint and completion gate."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.paths import plan_py_path
from cold_box_room.planning.plan_py import load_plan_py
from cold_box_room.planning.scoring import (
    PLAN_SCORE_MIN_PCT,
    all_steps_resolved,
    compute_plan_score,
)
from cold_box_room.r1.hallway import current_room, list_room_revisits, require_room
from cold_box_room.r1.paths import StagingError
from cold_box_room.r2.checkpoint import layer1_readonly_summary
from cold_box_room.room_3.analyst_log import parse_analyst_log, write_analyst_log
from cold_box_room.room_3.layer2_state import (
    MAX_PROMOTION_ATTEMPTS,
    load_layer2_state,
    record_layer2_complete,
    record_layer2_exit,
    record_submission_attempt,
)
from cold_box_room.room_3.logbook_paths import (
    layer2_analyst_log_md_path,
    layer2_skill_log_md_path,
    layer2_tool_log_md_path,
)
from cold_box_room.room_3.tool_log import read_layer2_tool_log
from cold_box_room.room_3.skill_log import (
    iter_skill_log_entries,
    read_skill_log,
    skill_run_audit_ids,
    successful_skill_run_ids,
)


class Layer2CheckpointError(StagingError):
    """Layer 2 completion gate failed."""


def _is_successful_skill_run(entry: dict[str, Any]) -> bool:
    if not entry.get("ok"):
        return False
    if int(entry.get("exit_code", -1)) != 0:
        return False
    if entry.get("error"):
        return False
    audit_ids = entry.get("audit_ids") or []
    return bool(audit_ids)


def count_successful_skill_runs(case_id: str) -> int:
    return sum(1 for row in iter_skill_log_entries(case_id) if _is_successful_skill_run(row))


def _plan_b_gate(case_id: str) -> dict[str, Any]:
    py_path = plan_py_path(case_id, room="b")
    if not py_path.is_file():
        return {
            "plan_present": False,
            "all_steps_resolved": False,
            "plan_score_gate": False,
            "plan_score_pct": 0.0,
            "plan_score": None,
        }

    doc = load_plan_py(py_path, room="b")
    score = compute_plan_score(doc)
    resolved = all_steps_resolved(doc)
    pct = float(score["plan_score_pct"])
    return {
        "plan_present": True,
        "all_steps_resolved": resolved,
        "plan_score_gate": resolved and pct >= PLAN_SCORE_MIN_PCT,
        "plan_score_pct": pct,
        "plan_score_min_pct": PLAN_SCORE_MIN_PCT,
        "plan_score": score,
    }


def layer2_readonly_summary(case_id: str) -> dict[str, Any]:
    """Layer 2 artifacts without requiring Room 3."""
    state = load_layer2_state(case_id)
    analyst = parse_analyst_log(case_id)
    successful = count_successful_skill_runs(case_id)
    self_score = analyst["self_score"] if analyst else None
    plan_gate = _plan_b_gate(case_id)
    analyst_complete = bool(analyst and analyst.get("complete"))
    score_gate = self_score is not None and self_score > 8
    layer1 = layer1_readonly_summary(case_id)

    return {
        "case_id": case_id,
        "layer1_context": {
            "findings": (layer1.get("analyst_log") or {}).get("findings", ""),
            "why": (layer1.get("analyst_log") or {}).get("why", ""),
            "self_score": layer1.get("self_score"),
            "successful_extractions": layer1.get("successful_extractions"),
        },
        "successful_skill_runs": successful,
        "skill_run_gate": successful >= 1,
        "plan_gate": plan_gate,
        "analyst_log": analyst,
        "self_score": self_score,
        "score_gate": score_gate,
        "analyst_log_complete": analyst_complete,
        "layer2_complete": bool(state.get("complete")),
        "room_revisits": list_room_revisits(case_id),
        "skill_log_path": str(read_skill_log(case_id)["jsonl_path"]),
        "skill_logbook_path": str(layer2_skill_log_md_path(case_id)),
        "tool_log_path": str(read_layer2_tool_log(case_id)["jsonl_path"]),
        "tool_logbook_path": str(layer2_tool_log_md_path(case_id)),
        "analyst_logbook_path": str(layer2_analyst_log_md_path(case_id)),
    }


def room3_checkpoint(case_id: str) -> dict[str, Any]:
    require_room(case_id, 3)
    state = load_layer2_state(case_id)
    analyst = parse_analyst_log(case_id)
    successful = count_successful_skill_runs(case_id)
    self_score = analyst["self_score"] if analyst else None

    skill_run_gate = successful >= 1
    analyst_complete = bool(analyst and analyst.get("complete"))
    score_gate = self_score is not None and self_score > 8
    plan_gate = _plan_b_gate(case_id)
    plan_resolved = plan_gate["all_steps_resolved"]
    plan_score_gate = plan_gate["plan_score_gate"]

    blocked: list[str] = []
    if state.get("complete"):
        blocked.append("layer2_already_complete")
    if state.get("exited"):
        blocked.append("layer2_exited")
    if not skill_run_gate:
        blocked.append("no_successful_skill_run")
    if not plan_gate["plan_present"]:
        blocked.append("plan_b_missing")
    elif not plan_resolved:
        blocked.append("plan_steps_unresolved")
    elif not plan_score_gate:
        blocked.append("plan_score_below_70")
    if not analyst_complete:
        blocked.append("analyst_log_incomplete")
    if analyst_complete and not score_gate:
        blocked.append("self_score_not_above_8")

    revisits = list_room_revisits(case_id)
    if revisits and analyst_complete:
        corrections = (analyst or {}).get("corrections", "").strip().lower()
        if not corrections or corrections in {"none", "n/a", "no corrections"}:
            blocked.append("corrections_required_after_revisit")

    ready = (
        skill_run_gate
        and plan_score_gate
        and analyst_complete
        and score_gate
        and not state.get("complete")
        and not state.get("exited")
        and "corrections_required_after_revisit" not in blocked
    )

    return {
        "case_id": case_id,
        "room": 3,
        "successful_skill_runs": successful,
        "skill_run_gate": skill_run_gate,
        "plan_gate": plan_gate,
        "plan_resolved_gate": plan_resolved,
        "plan_score_gate": plan_score_gate,
        "analyst_log": analyst,
        "self_score": self_score,
        "score_gate": score_gate,
        "promotion_attempts": int(state.get("promotion_attempts", 0)),
        "max_attempts": MAX_PROMOTION_ATTEMPTS,
        "attempts_remaining": max(
            0, MAX_PROMOTION_ATTEMPTS - int(state.get("promotion_attempts", 0))
        ),
        "layer2_complete": bool(state.get("complete")),
        "room_revisits": revisits,
        "ready_for_complete": ready,
        "blocked_reasons": blocked,
        "layer1_summary": layer1_readonly_summary(case_id),
        "skill_log_path": str(read_skill_log(case_id)["jsonl_path"]),
        "skill_logbook_path": str(layer2_skill_log_md_path(case_id)),
        "tool_log_path": str(read_layer2_tool_log(case_id)["jsonl_path"]),
        "tool_logbook_path": str(layer2_tool_log_md_path(case_id)),
        "analyst_logbook_path": str(layer2_analyst_log_md_path(case_id)),
    }


def submit_layer2_writeup(
    *,
    case_id: str,
    findings: str,
    self_score: int,
    why: str,
    corrections: str,
) -> dict[str, Any]:
    require_room(case_id, 3)
    state = load_layer2_state(case_id)
    if state.get("exited"):
        return {
            "ok": False,
            "error": "Layer 2 already exited — cannot submit another write-up.",
            "checkpoint": room3_checkpoint(case_id),
        }
    if state.get("complete"):
        return {
            "ok": False,
            "error": "Layer 2 already complete — case finished.",
            "checkpoint": room3_checkpoint(case_id),
        }

    write_info = write_analyst_log(
        case_id=case_id,
        findings=findings,
        self_score=self_score,
        why=why,
        corrections=corrections,
    )
    checkpoint = room3_checkpoint(case_id)

    if checkpoint["ready_for_complete"]:
        record_layer2_complete(case_id, reason="Layer 2 gates passed")
        checkpoint = room3_checkpoint(case_id)
        return {
            "ok": True,
            "complete": True,
            "room": 3,
            "write_up": write_info,
            "checkpoint": checkpoint,
        }

    state = record_submission_attempt(case_id, self_score=write_info["self_score"])
    checkpoint = room3_checkpoint(case_id)
    checkpoint["promotion_attempts"] = state["promotion_attempts"]

    result: dict[str, Any] = {
        "ok": False,
        "complete": False,
        "room": 3,
        "write_up": write_info,
        "checkpoint": checkpoint,
        "blocked_reasons": checkpoint["blocked_reasons"],
    }

    if int(state["promotion_attempts"]) >= MAX_PROMOTION_ATTEMPTS:
        result["attempts_exhausted"] = True
        result["hint"] = (
            "Three completion attempts used. Call exit_layer2 with why you cannot complete Layer 2."
        )
    else:
        result["attempts_exhausted"] = False
        result["hint"] = (
            "Resolve blocked_reasons, mark plan_b steps, run skills, then submit_layer2_writeup again."
        )

    return result


def apply_plan_b_step_status(
    *,
    case_id: str,
    step_id: int,
    status: str,
    proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from cold_box_room.planning.harness import PlanHarnessError, apply_step_status

    require_room(case_id, 3)
    allowed_runs = successful_skill_run_ids(case_id)
    allowed_audits = skill_run_audit_ids(case_id)

    proof = dict(proof or {})
    if status.strip().lower() == "passed":
        run_id = str(proof.get("run_id") or "").strip()
        audit_id = str(proof.get("audit_id") or "").strip()
        if run_id and run_id not in allowed_runs:
            raise PlanHarnessError(f"run_id {run_id!r} not in successful Layer 2 skill log")
        if audit_id and audit_id not in allowed_audits:
            raise PlanHarnessError(f"audit_id {audit_id!r} not tied to a successful skill run")
        if not run_id and not audit_id:
            raise PlanHarnessError("passed requires proof.run_id or proof.audit_id from skill log")
        if run_id and not audit_id:
            entry = next(
                (row for row in iter_skill_log_entries(case_id) if row.get("run_id") == run_id),
                None,
            )
            aids = list((entry or {}).get("audit_ids") or [])
            if aids:
                proof["audit_id"] = aids[0]
                proof.setdefault("exit_code", 0)
                if not proof.get("scratch_refs") and not proof.get("scratch_relpath"):
                    proof["scratch_refs"] = [f"{aids[0]}/stdout.txt"]

    try:
        return apply_step_status(
            case_id=case_id,
            room="b",
            step_id=step_id,
            status=status,
            proof=proof,
            allowed_session_audit_ids=allowed_audits if status.strip().lower() == "passed" else None,
        )
    except PlanHarnessError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id, "step_id": step_id}


def exit_layer2(*, case_id: str, reason: str) -> dict[str, Any]:
    require_room(case_id, 3)
    state = load_layer2_state(case_id)
    if not reason.strip():
        raise Layer2CheckpointError("exit reason must not be empty")
    if int(state.get("promotion_attempts", 0)) < MAX_PROMOTION_ATTEMPTS:
        raise Layer2CheckpointError(
            f"exit_layer2 allowed only after {MAX_PROMOTION_ATTEMPTS} failed completion attempts"
        )
    if state.get("exited"):
        return {
            "ok": True,
            "already_exited": True,
            "exit_reason": state.get("exit_reason"),
            "room": current_room(case_id),
        }

    updated = record_layer2_exit(case_id, reason)
    return {
        "ok": True,
        "exited": True,
        "room": 3,
        "exit_reason": updated["exit_reason"],
        "message": "Case ends in Room 3 — Layer 2 incomplete.",
    }


def extend_plan_b_step(
    *,
    case_id: str,
    title: str,
    reason: str,
    tool_id: str = "",
) -> dict[str, Any]:
    from cold_box_room.planning.extend import PlanExtendError, extend_plan_step

    require_room(case_id, 3)
    try:
        return extend_plan_step(
            case_id=case_id,
            room="b",
            title=title,
            reason=reason,
            tool_id=tool_id,
        )
    except PlanExtendError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}
