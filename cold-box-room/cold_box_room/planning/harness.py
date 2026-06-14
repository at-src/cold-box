"""Harness sets pass/fail on plan steps during R2 execution (not in planning room)."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.models import FINAL_STATUSES
from cold_box_room.planning.paths import plan_py_path
from cold_box_room.planning.plan_py import load_plan_py, update_step_in_plan
from cold_box_room.planning.scoring import all_steps_resolved, compute_plan_score


class PlanHarnessError(Exception):
    """Invalid harness status transition or proof."""


def _validate_pass_proof(proof: dict[str, Any]) -> None:
    audit_id = str(proof.get("audit_id") or "").strip()
    scratch_refs = proof.get("scratch_refs") or []
    exit_code = proof.get("exit_code")
    if not audit_id:
        raise PlanHarnessError("passed requires proof.audit_id")
    if exit_code is not None and int(exit_code) != 0:
        raise PlanHarnessError("passed requires exit_code 0")
    if not scratch_refs and not str(proof.get("scratch_relpath") or "").strip():
        raise PlanHarnessError("passed requires scratch_refs or scratch_relpath")


def _validate_note_proof(proof: dict[str, Any], label: str) -> None:
    note = str(proof.get("note") or proof.get("reason") or "").strip()
    if not note:
        raise PlanHarnessError(f"{label} requires proof.note")


def apply_step_status(
    *,
    case_id: str,
    room: str,
    step_id: int,
    status: str,
    proof: dict[str, Any] | None = None,
    allowed_session_audit_ids: set[str] | None = None,
) -> dict[str, Any]:
    proof = dict(proof or {})
    status = status.strip().lower()
    if status not in FINAL_STATUSES | {"held_for_later"}:
        raise PlanHarnessError(f"invalid status {status!r}")

    if status == "passed":
        _validate_pass_proof(proof)
        audit_id = str(proof.get("audit_id") or "").strip()
        if allowed_session_audit_ids is not None and audit_id not in allowed_session_audit_ids:
            raise PlanHarnessError(f"audit_id {audit_id!r} not in this session's tool log")
    elif status == "fail":
        _validate_note_proof(proof, "fail")
    elif status == "not_relevant":
        _validate_note_proof(proof, "not_relevant")

    path = plan_py_path(case_id, room=room)
    doc = update_step_in_plan(path, room=room, step_id=step_id, status=status, proof=proof)
    score = compute_plan_score(doc)
    return {
        "ok": True,
        "case_id": case_id,
        "room": room.upper(),
        "step_id": step_id,
        "status": status,
        "proof": proof,
        "plan_score": score,
        "all_steps_resolved": all_steps_resolved(doc),
    }
