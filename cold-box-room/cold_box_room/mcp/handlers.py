"""MCP tool handlers — thin wrappers over registry and R2 harness."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.checkpoint import PlanningCheckpointError
from cold_box_room.planning.extend import PlanExtendError, extend_plan_step
from cold_box_room.planning.harness import PlanHarnessError
from cold_box_room.r1.paths import StagingError
from cold_box_room.r2.checkpoint import (
    exit_layer1,
    layer1_readonly_summary,
    r2_layer1_checkpoint,
    submit_layer1_writeup,
)
from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.executor import run_sift_tool as execute_sift_tool
from cold_box_room.r2.scratch_analysis import run_scratch_analysis
from cold_box_room.r2.analyst_log import read_analyst_log
from cold_box_room.r2.tool_log import read_tool_log, iter_tool_log_entries
from cold_box_room.room_a import (
    apply_plan_a_step_status,
    formalize_plan_a,
    get_plan_a_status,
    write_plan_a_md,
)
from cold_box_room.room_b import (
    formalize_plan_b,
    get_plan_b_status,
    write_plan_b_md,
)
from cold_box_room.tools.registry import (
    ToolCatalogError,
    describe_tool,
    list_categories,
    list_tools_dict,
)


def handle_list_sift_tools(
    *,
    category: str = "",
    runnable_only: bool = True,
) -> dict[str, Any]:
    tools = list_tools_dict(
        category=category or None,
        runnable_only=runnable_only,
    )
    return {
        "tools": tools,
        "count": len(tools),
        "categories": list_categories(),
        "legend": {
            "ok": "lab tested",
            "not_tested": "not lab auto-tested — runnable if verification.runnable is true",
            "unavailable": "not installed on host",
            "bad": "do not use",
        },
    }


def handle_describe_sift_tool(tool_id: str) -> dict[str, Any]:
    try:
        return describe_tool(tool_id)
    except ToolCatalogError as exc:
        return {"ok": False, "error": str(exc)}


def handle_run_sift_tool(
    *,
    tool_id: str,
    case_id: str,
    input_relpath: str,
    purpose: str,
    why: str,
    extra_args: list[str] | None = None,
    timeout: int = 0,
) -> dict[str, Any]:
    try:
        return execute_sift_tool(
            tool_id=tool_id,
            case_id=case_id,
            input_relpath=input_relpath,
            purpose=purpose,
            why=why,
            extra_args=extra_args,
            timeout=timeout or None,
        )
    except (ToolExecutionError, StagingError, ValueError) as exc:
        return {
            "ok": False,
            "error": str(exc),
            "tool_id": tool_id,
            "case_id": case_id,
        }


def handle_analyze_scratch(
    *,
    case_id: str,
    binary: str,
    scratch_relpath: str,
    purpose: str,
    why: str,
    args: list[str] | None = None,
    timeout: int = 0,
) -> dict[str, Any]:
    try:
        return run_scratch_analysis(
            case_id=case_id,
            binary=binary,
            scratch_relpath=scratch_relpath,
            args=args,
            purpose=purpose,
            why=why,
            timeout=timeout or None,
        )
    except (ToolExecutionError, StagingError, ValueError) as exc:
        return {
            "ok": False,
            "error": str(exc),
            "case_id": case_id,
            "binary": binary,
        }


def handle_read_layer1_tool_log(case_id: str, limit: int = 20) -> dict[str, Any]:
    try:
        from cold_box_room.r1.hallway import current_room

        log = read_tool_log(case_id, limit=limit)
        room = current_room(case_id)
        if room == "2":
            log["checkpoint"] = r2_layer1_checkpoint(case_id)
        else:
            log["layer1_summary"] = layer1_readonly_summary(case_id)
        return log
    except StagingError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_read_layer1_analyst_log(case_id: str) -> dict[str, Any]:
    try:
        analyst = read_analyst_log(case_id)
        return {"ok": True, "case_id": case_id, "analyst_log": analyst}
    except StagingError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_get_layer1_status(case_id: str) -> dict[str, Any]:
    try:
        from cold_box_room.r1.hallway import current_room

        analyst = read_analyst_log(case_id)
        room = current_room(case_id)
        if room == "2":
            checkpoint = r2_layer1_checkpoint(case_id)
            return {
                "checkpoint": checkpoint,
                "analyst_log": analyst,
            }
        return {
            "readonly": True,
            "layer1_summary": layer1_readonly_summary(case_id),
            "analyst_log": analyst,
        }
    except StagingError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_submit_layer1_writeup(
    *,
    case_id: str,
    findings: str,
    self_score: int,
    why: str,
) -> dict[str, Any]:
    try:
        return submit_layer1_writeup(
            case_id=case_id,
            findings=findings,
            self_score=self_score,
            why=why,
        )
    except StagingError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_exit_layer1(*, case_id: str, reason: str) -> dict[str, Any]:
    try:
        return exit_layer1(case_id=case_id, reason=reason)
    except StagingError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_write_plan_a_md(*, case_id: str, markdown: str) -> dict[str, Any]:
    try:
        return write_plan_a_md(case_id=case_id, markdown=markdown)
    except PlanningCheckpointError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_formalize_plan_a(case_id: str) -> dict[str, Any]:
    try:
        result = formalize_plan_a(case_id=case_id)
    except PlanningCheckpointError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}

    if result.get("ready_for_room2"):
        try:
            from cold_box_room.r1.hallway import current_room, promote_to_room2
            if current_room(case_id) == "A":
                hallway = promote_to_room2(case_id)
                result["promoted"] = True
                result["room"] = "2"
                result["hallway"] = hallway
                result["next_step"] = "run_sift_tool"
        except Exception as exc:
            result["promotion_error"] = str(exc)

    return result


def handle_apply_plan_a_step_status(
    *,
    case_id: str,
    step_id: int,
    status: str,
    proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    audit_ids = {str(row.get("audit_id") or "") for row in iter_tool_log_entries(case_id)}
    audit_ids.discard("")
    try:
        return apply_plan_a_step_status(
            case_id=case_id,
            step_id=step_id,
            status=status,
            proof=proof,
            allowed_session_audit_ids=audit_ids,
        )
    except PlanHarnessError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id, "step_id": step_id}


def handle_get_plan_a_status(case_id: str) -> dict[str, Any]:
    try:
        return get_plan_a_status(case_id)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_extend_plan_a_step(
    *,
    case_id: str,
    title: str,
    reason: str,
    tool_id: str = "",
) -> dict[str, Any]:
    try:
        return extend_plan_step(
            case_id=case_id,
            room="a",
            title=title,
            reason=reason,
            tool_id=tool_id,
        )
    except PlanExtendError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_write_plan_b_md(*, case_id: str, markdown: str) -> dict[str, Any]:
    try:
        return write_plan_b_md(case_id=case_id, markdown=markdown)
    except PlanningCheckpointError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_formalize_plan_b(case_id: str) -> dict[str, Any]:
    try:
        result = formalize_plan_b(case_id=case_id)
    except PlanningCheckpointError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}

    if result.get("ready_for_room3"):
        try:
            from cold_box_room.r1.hallway import current_room, promote_to_room3
            if current_room(case_id) == "B":
                hallway = promote_to_room3(case_id)
                result["promoted"] = True
                result["room"] = "3"
                result["hallway"] = hallway
                result["next_step"] = "run_skill"
        except Exception as exc:
            result["promotion_error"] = str(exc)

    return result


def handle_get_plan_b_status(case_id: str) -> dict[str, Any]:
    try:
        return get_plan_b_status(case_id)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}
