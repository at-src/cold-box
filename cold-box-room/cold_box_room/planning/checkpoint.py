"""Planning room checkpoint — gate before entering execution room."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.formalize import FormalizePlanError, formalize_plan
from cold_box_room.planning.markdown import parse_plan_md
from cold_box_room.planning.paths import plan_md_path, plan_py_path
from cold_box_room.planning.plan_py import (
    load_plan_py,
    plans_match,
    validate_plan_structure,
)
from cold_box_room.planning.scoring import all_steps_resolved, compute_plan_score
from cold_box_room.planning.state import plan_was_formalized


class PlanningCheckpointError(Exception):
    """Planning room promotion gate failed."""


def write_plan_md(*, case_id: str, markdown: str, room: str = "a") -> dict[str, Any]:
    """Agent drafts plan_{room}.md — notebook step only (no py, no gate)."""
    if not markdown.strip():
        raise PlanningCheckpointError("plan markdown is empty")
    doc = parse_plan_md(markdown, case_id=case_id, room=room)
    if not doc.steps:
        raise PlanningCheckpointError("plan must include at least one step")

    path = plan_md_path(case_id, room=room)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = markdown if markdown.endswith("\n") else markdown + "\n"
    path.write_text(text, encoding="utf-8")

    return {
        "ok": True,
        "case_id": case_id,
        "room": room.upper(),
        "plan_md": str(path),
        "step_count": len(doc.steps),
        "next_step": f"formalize_plan_{room.lower()}",
    }


def formalize_plan_md(*, case_id: str, room: str = "a") -> dict[str, Any]:
    """Typewriter step — read plan_{room}.md, validate format, write plan_{room}.py."""
    try:
        result = formalize_plan(case_id=case_id, room=room)
    except FormalizePlanError as exc:
        raise PlanningCheckpointError(str(exc)) from exc

    checkpoint = planning_checkpoint(case_id, room=room)
    ready_key = "ready_for_room2" if room.lower() == "a" else "ready_for_room3"
    gate_open = bool(checkpoint.get(ready_key))

    return {
        **result,
        "plan_formalized": True,
        "plan_formalized_at": result["plan_formalized_at"],
        "checkpoint": checkpoint,
        ready_key: gate_open,
        "next_step": ready_key if gate_open else "revise_plan_md",
    }


def planning_checkpoint(case_id: str, *, room: str = "a") -> dict[str, Any]:
    """Gates for Room A → R2 or Room B → Room 3 (same code, different room letter)."""
    md_path = plan_md_path(case_id, room=room)
    py_path = plan_py_path(case_id, room=room)
    blocked: list[str] = []

    formalized = plan_was_formalized(case_id, room=room)
    if not formalized:
        blocked.append("plan_not_formalized")

    md_valid = False
    py_valid = False
    plans_aligned = False
    step_count = 0
    md_doc = None
    py_doc = None

    if not md_path.is_file():
        blocked.append(f"plan_{room.lower()}_md_missing")
    else:
        try:
            md_doc = parse_plan_md(md_path.read_text(encoding="utf-8"), case_id=case_id, room=room)
            md_valid = True
            step_count = len(md_doc.steps)
            if step_count < 1:
                blocked.append("plan_has_no_steps")
        except (ValueError, OSError) as exc:
            blocked.append(f"plan_{room.lower()}_md_invalid:{exc}")

    if not py_path.is_file():
        blocked.append(f"plan_{room.lower()}_py_missing")
        if "plan_not_formalized" not in blocked:
            blocked.append("plan_not_formalized")
    else:
        try:
            py_doc = load_plan_py(py_path, room=room)
            py_errors = validate_plan_structure(py_doc)
            if py_errors:
                blocked.append(f"plan_{room.lower()}_py_invalid:" + "; ".join(py_errors))
            else:
                py_valid = True
        except (ValueError, OSError, SyntaxError) as exc:
            blocked.append(f"plan_{room.lower()}_py_invalid:{exc}")

    if md_valid and py_valid and md_doc and py_doc:
        mismatch = plans_match(md_doc, py_doc)
        if mismatch:
            blocked.append("plan_md_py_mismatch:" + "; ".join(mismatch))
        else:
            plans_aligned = True

    ready = (
        formalized
        and md_valid
        and py_valid
        and plans_aligned
        and step_count >= 1
        and "plan_has_no_steps" not in blocked
    )

    ready_key = "ready_for_room2" if room.upper() == "A" else "ready_for_room3"
    score = compute_plan_score(py_doc) if py_doc else None

    payload: dict[str, Any] = {
        "case_id": case_id,
        "room": room.upper(),
        "plan_md": str(md_path),
        "plan_py": str(py_path),
        "step_count": step_count,
        "plan_formalized": formalized and py_valid and plans_aligned,
        "plan_md_valid": md_valid,
        "plan_py_valid": py_valid,
        "plans_aligned": plans_aligned,
        ready_key: ready,
        "blocked_reasons": blocked,
        "plan_score": score,
        "all_steps_resolved": all_steps_resolved(py_doc) if py_doc else False,
    }
    return payload
