"""Formalize plan_*.md into plan_*.py checkbox file (harness script, not agent)."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.markdown import parse_plan_md
from cold_box_room.planning.paths import plan_md_path, plan_py_path
from cold_box_room.planning.plan_py import (
    load_plan_py,
    merge_execution_state,
    plans_match,
    validate_plan_structure,
    write_plan_py,
)
from cold_box_room.planning.state import record_plan_formalized


class FormalizePlanError(Exception):
    """Could not convert plan md to plan py."""


def formalize_plan(*, case_id: str, room: str = "a") -> dict[str, Any]:
    """Convert plan_{room}.md → plan_{room}.py with pending checkbox steps."""
    md_path = plan_md_path(case_id, room=room)
    py_path = plan_py_path(case_id, room=room)
    if not md_path.is_file():
        raise FormalizePlanError(f"missing {md_path}")

    md_text = md_path.read_text(encoding="utf-8")
    md_doc = parse_plan_md(md_text, case_id=case_id, room=room)
    structure_errors = validate_plan_structure(md_doc)
    if structure_errors:
        raise FormalizePlanError("; ".join(structure_errors))

    doc = md_doc
    if py_path.is_file():
        existing = load_plan_py(py_path, room=room)
        doc = merge_execution_state(md_doc, existing)

    write_plan_py(py_path, doc, room=room)

    py_doc = load_plan_py(py_path, room=room)
    mismatch = plans_match(md_doc, py_doc)
    if mismatch:
        raise FormalizePlanError("formalize mismatch: " + "; ".join(mismatch))

    formalize_meta = record_plan_formalized(case_id, room=room)

    return {
        "ok": True,
        "case_id": case_id,
        "room": room.upper(),
        "plan_md": str(md_path),
        "plan_py": str(py_path),
        "step_count": len(doc.steps),
        "plan_formalized_at": formalize_meta["plan_formalized_at"],
    }
