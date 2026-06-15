"""Load and write plan_a.py / plan_b.py — checkbox gates for harness."""

from __future__ import annotations

import ast
import pprint
from pathlib import Path
from typing import Any

from cold_box_room.planning.models import PlanDocument, PlanStep
from cold_box_room.planning.paths import plan_var_name


def write_plan_py(path: Path, doc: PlanDocument, *, room: str) -> None:
    var = plan_var_name(room)
    payload = pprint.pformat(
        doc.to_plan_dict(),
        width=120,
        indent=2,
        sort_dicts=False,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'"""Room {room.upper()} plan — harness updates step status/proof during execution."""\n\n'
        f"{var} = {payload}\n",
        encoding="utf-8",
    )


def load_plan_py(path: Path, *, room: str) -> PlanDocument:
    if not path.is_file():
        raise FileNotFoundError(f"missing {path}")
    var = plan_var_name(room)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var:
                    value = ast.literal_eval(node.value)
                    if not isinstance(value, dict):
                        raise ValueError(f"{var} must be a dict")
                    return PlanDocument.from_plan_dict(value, room=room)
    raise ValueError(f"{path} must define {var} = {{...}}")


def validate_plan_structure(doc: PlanDocument) -> list[str]:
    errors: list[str] = []
    if not doc.case_id.strip():
        errors.append("plan case_id is empty")
    if not doc.steps:
        errors.append("plan has no steps")
    ids = [s.step_id for s in doc.steps]
    if ids != list(range(1, len(doc.steps) + 1)):
        errors.append(f"step ids must be contiguous 1..N, got {ids}")
    for step in doc.steps:
        if not step.title:
            errors.append(f"step {step.step_id} missing title")
        if not step.reason:
            errors.append(f"step {step.step_id} missing reason")
        if step.status not in {
            "pending",
            "passed",
            "fail",
            "not_relevant",
            "held_for_later",
        }:
            errors.append(f"step {step.step_id} invalid status {step.status!r}")
    return errors


def plans_match(md_doc: PlanDocument, py_doc: PlanDocument) -> list[str]:
    errors: list[str] = []
    if md_doc.case_id and py_doc.case_id and md_doc.case_id != py_doc.case_id:
        errors.append(f"case_id mismatch: md={md_doc.case_id!r} py={py_doc.case_id!r}")
    if len(md_doc.steps) != len(py_doc.steps):
        errors.append(f"step count mismatch: md={len(md_doc.steps)} py={len(py_doc.steps)}")
        return errors
    for md_step, py_step in zip(md_doc.steps, py_doc.steps):
        if md_step.step_id != py_step.step_id:
            errors.append(f"step id order mismatch at {md_step.step_id} vs {py_step.step_id}")
        if md_step.title != py_step.title:
            errors.append(f"step {md_step.step_id} title mismatch")
        if md_step.reason != py_step.reason:
            errors.append(f"step {md_step.step_id} reason mismatch")
        if md_step.tool_id != py_step.tool_id:
            errors.append(f"step {md_step.step_id} tool_id mismatch")
        if md_step.purpose != py_step.purpose:
            errors.append(f"step {md_step.step_id} purpose mismatch")
    return errors


def merge_execution_state(base: PlanDocument, current: PlanDocument) -> PlanDocument:
    by_id = {s.step_id: s for s in current.steps}
    merged: list[PlanStep] = []
    for step in base.steps:
        existing = by_id.get(step.step_id)
        if existing is None:
            merged.append(step)
            continue
        merged.append(
            PlanStep(
                step_id=step.step_id,
                title=step.title,
                reason=step.reason,
                tool_id=step.tool_id,
                purpose=step.purpose,
                status=existing.status,
                proof=dict(existing.proof),
            )
        )
    return PlanDocument(
        case_id=base.case_id,
        room=base.room,
        steps=merged,
        attestation=base.attestation,
    )


def update_step_in_plan(
    path: Path,
    *,
    room: str,
    step_id: int,
    **updates: Any,
) -> PlanDocument:
    doc = load_plan_py(path, room=room)
    new_steps: list[PlanStep] = []
    found = False
    for step in doc.steps:
        if step.step_id != step_id:
            new_steps.append(step)
            continue
        found = True
        proof = dict(step.proof)
        if "proof" in updates:
            proof = dict(updates.pop("proof") or {})
        new_steps.append(
            PlanStep(
                step_id=step.step_id,
                title=step.title,
                reason=step.reason,
                tool_id=step.tool_id,
                purpose=step.purpose,
                status=str(updates.get("status", step.status)),
                proof=proof,
            )
        )
    if not found:
        raise ValueError(f"unknown step id {step_id}")
    updated = PlanDocument(
        case_id=doc.case_id,
        room=doc.room,
        steps=new_steps,
        attestation=doc.attestation,
    )
    write_plan_py(path, updated, room=room)
    return updated


def stamp_tools_attestation(path: Path, *, room: str, value: str) -> PlanDocument:
    doc = load_plan_py(path, room=room)
    doc.attestation.tools_catalog_reviewed = value.strip()
    write_plan_py(path, doc, room=room)
    return doc
