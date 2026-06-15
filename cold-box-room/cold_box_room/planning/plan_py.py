"""Load and write plan_a.py / plan_b.py — checkbox gates for harness."""

from __future__ import annotations

import ast
import contextlib
import fcntl
import json
import shutil
from pathlib import Path
from typing import Any, Callable, Iterator

from cold_box_room.planning.models import PlanDocument, PlanStep
from cold_box_room.planning.paths import plan_var_name

_PLAN_HEADER = '"""Room {room} plan — harness updates step status/proof during execution."""'


@contextlib.contextmanager
def _plan_py_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Serialize plan file reads/writes — parallel apply_plan_* must not race."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(
            lock_file.fileno(),
            fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
        )
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _json_literal(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        raise ValueError("plan payload must be a plain string literal")
    raise ValueError(f"unsupported plan payload literal: {type(node).__name__}")


def _payload_from_assign_value(node: ast.AST) -> dict[str, Any]:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if (
            node.func.attr == "loads"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "json"
            and node.args
        ):
            payload = json.loads(_json_literal(node.args[0]))
            if not isinstance(payload, dict):
                raise ValueError("json.loads plan payload must be a dict")
            return payload
    value = ast.literal_eval(node)
    if not isinstance(value, dict):
        raise ValueError("plan payload must be a dict")
    return value


def _read_plan_payload(path: Path, *, room: str) -> dict[str, Any]:
    var = plan_var_name(room)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var:
                    return _payload_from_assign_value(node.value)
    raise ValueError(f"{path} must define {var} = json.loads(...) or a dict literal")


def _load_unlocked(path: Path, *, room: str) -> PlanDocument:
    try:
        payload = _read_plan_payload(path, room=room)
    except (SyntaxError, ValueError, json.JSONDecodeError) as exc:
        backup = path.with_suffix(path.suffix + ".bak")
        if backup.is_file():
            try:
                payload = _read_plan_payload(backup, room=room)
            except (SyntaxError, ValueError, json.JSONDecodeError):
                raise exc
        else:
            raise
    return PlanDocument.from_plan_dict(payload, room=room)


def _write_unlocked(path: Path, doc: PlanDocument, *, room: str) -> None:
    var = plan_var_name(room)
    payload = json.dumps(doc.to_plan_dict(), indent=2, ensure_ascii=False)
    body = (
        f"{_PLAN_HEADER.format(room=room.upper())}\n\n"
        "import json\n\n"
        f"{var} = json.loads({json.dumps(payload)})\n"
    )
    if path.is_file():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.write_text(body, encoding="utf-8")


def write_plan_py(path: Path, doc: PlanDocument, *, room: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _plan_py_lock(path, exclusive=True):
        _write_unlocked(path, doc, room=room)


def load_plan_py(path: Path, *, room: str) -> PlanDocument:
    if not path.is_file():
        raise FileNotFoundError(f"missing {path}")
    with _plan_py_lock(path, exclusive=False):
        return _load_unlocked(path, room=room)


def mutate_plan_py(
    path: Path,
    *,
    room: str,
    mutate: Callable[[PlanDocument], PlanDocument],
) -> PlanDocument:
    """Load → mutate → save under one exclusive lock (safe for parallel tool dispatch)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _plan_py_lock(path, exclusive=True):
        doc = _load_unlocked(path, room=room)
        updated = mutate(doc)
        _write_unlocked(path, updated, room=room)
        return updated


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
    def _mutate(doc: PlanDocument) -> PlanDocument:
        new_steps: list[PlanStep] = []
        found = False
        for step in doc.steps:
            if step.step_id != step_id:
                new_steps.append(step)
                continue
            found = True
            proof = dict(step.proof)
            local_updates = dict(updates)
            if "proof" in local_updates:
                proof = dict(local_updates.pop("proof") or {})
            new_steps.append(
                PlanStep(
                    step_id=step.step_id,
                    title=step.title,
                    reason=step.reason,
                    tool_id=step.tool_id,
                    purpose=step.purpose,
                    status=str(local_updates.get("status", step.status)),
                    proof=proof,
                )
            )
        if not found:
            raise ValueError(f"unknown step id {step_id}")
        return PlanDocument(
            case_id=doc.case_id,
            room=doc.room,
            steps=new_steps,
            attestation=doc.attestation,
        )

    return mutate_plan_py(path, room=room, mutate=_mutate)


def stamp_tools_attestation(path: Path, *, room: str, value: str) -> PlanDocument:
    def _mutate(doc: PlanDocument) -> PlanDocument:
        doc.attestation.tools_catalog_reviewed = value.strip()
        return doc

    return mutate_plan_py(path, room=room, mutate=_mutate)
