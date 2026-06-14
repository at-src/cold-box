"""Harness execution for skill scripts (Room 3 only)."""

from __future__ import annotations

from typing import Any

from cold_box_room.r1.hallway import require_room
from cold_box_room.skills.registry import SkillCatalogError, get_skill
from cold_box_room.skills.skill_runner import run_skill_script


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
                f"Skill {rec.skill_id!r} is reference-only (tier 3) — browse describe_skill "
                "for the playbook; use run_sift_tool in Room 2 for extraction."
            ),
            "case_id": case_id,
            "skill_id": rec.skill_id,
            "reference_only": True,
        }

    rel = input_relpath.strip().lstrip("/")
    if not rel:
        return {
            "ok": False,
            "error": "input_relpath must name a file inside the R2 sandbox",
            "case_id": case_id,
            "skill_id": rec.skill_id,
        }

    result = run_skill_script(
        case_id=case_id,
        skill_ref=rec.skill_id,
        input_relpath=rel,
        journal_id=journal_id or rec.journal_id,
        script_args=list(script_args or []),
    )
    result["case_id"] = case_id
    if purpose.strip():
        result["purpose"] = purpose.strip()
    if why.strip():
        result["why"] = why.strip()
    return result
