"""Harness execution for skill scripts (Room 3 only)."""

from __future__ import annotations

from typing import Any

from cold_box_room.r1.hallway import require_room
from cold_box_room.skills.registry import SkillCatalogError, get_skill, is_agent_runnable
from cold_box_room.skills.skill_runner import run_skill_script
from cold_box_room.room_3.skill_log import append_skill_log, next_skill_run_id


class SkillExecutionError(ValueError):
    pass


def run_skill(
    *,
    skill_id: str,
    case_id: str,
    input_relpath: str,
    purpose: str = "",
    why: str = "",
    journal_id: str = "",
    script_args: list[str] | None = None,
    plan_step_id: int | None = None,
) -> dict[str, Any]:
    require_room(case_id, 3)
    try:
        rec = get_skill(skill_id)
    except SkillCatalogError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}

    if rec.reference_only or not rec.has_script:
        return {
            "ok": False,
            "error": (
                f"Skill {rec.skill_id!r} is reference-only — browse describe_skill "
                "for the playbook; use run_sift_tool in Room 2 for extraction."
            ),
            "case_id": case_id,
            "skill_id": rec.skill_id,
            "reference_only": True,
        }

    if not is_agent_runnable(rec):
        return {
            "ok": False,
            "error": (
                f"Skill {rec.skill_id!r} is excluded from the agent catalog "
                f"(execution_mode={rec.execution_mode!r}). Pick a fully SIFT-mapped skill."
            ),
            "case_id": case_id,
            "skill_id": rec.skill_id,
            "execution_mode": rec.execution_mode,
        }

    rel = input_relpath.strip().lstrip("/")
    if not rel:
        return {
            "ok": False,
            "error": "input_relpath must name a file inside the R2 sandbox",
            "case_id": case_id,
            "skill_id": rec.skill_id,
        }

    run_id = next_skill_run_id()
    result = run_skill_script(
        case_id=case_id,
        skill_ref=rec.skill_id,
        input_relpath=rel,
        journal_id=journal_id or rec.journal_id,
        script_args=list(script_args or []),
        skill_run_id=run_id,
    )
    ok = bool(result.get("ok"))
    audit_ids = list(result.get("audit_ids") or [])
    exit_code = 0 if ok else 1
    append_skill_log(
        case_id=case_id,
        run_id=run_id,
        skill_id=rec.skill_id,
        journal_id=result.get("journal_id") or rec.journal_id,
        library_slug=rec.library_slug,
        input_relpath=rel,
        ok=ok and bool(audit_ids),
        audit_ids=audit_ids,
        exit_code=exit_code,
        purpose=purpose.strip(),
        why=why.strip(),
        error=str(result.get("error") or ""),
        plan_step_id=plan_step_id,
    )

    result["case_id"] = case_id
    result["run_id"] = run_id
    if purpose.strip():
        result["purpose"] = purpose.strip()
    if why.strip():
        result["why"] = why.strip()
    if plan_step_id is not None:
        result["plan_step_id"] = plan_step_id
    if ok and not audit_ids:
        result["ok"] = False
        result["error"] = "Skill script finished without harness tool runs — cannot mark plan step passed."
    return result
