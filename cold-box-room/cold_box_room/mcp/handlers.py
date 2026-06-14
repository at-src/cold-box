"""MCP tool handlers — thin wrappers over registry and R2 harness."""

from __future__ import annotations

from typing import Any

from cold_box_room.r1.paths import StagingError
from cold_box_room.r2.checkpoint import exit_layer1, r2_layer1_checkpoint, submit_layer1_writeup
from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.executor import run_sift_tool as execute_sift_tool
from cold_box_room.r2.scratch_analysis import run_scratch_analysis
from cold_box_room.r2.analyst_log import read_analyst_log
from cold_box_room.r2.tool_log import read_tool_log
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
    except (ToolExecutionError, StagingError) as exc:
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
    except (ToolExecutionError, StagingError) as exc:
        return {
            "ok": False,
            "error": str(exc),
            "case_id": case_id,
            "binary": binary,
        }


def handle_read_layer1_tool_log(case_id: str, limit: int = 20) -> dict[str, Any]:
    try:
        log = read_tool_log(case_id, limit=limit)
        log["checkpoint"] = r2_layer1_checkpoint(case_id)
        return log
    except StagingError as exc:
        return {"ok": False, "error": str(exc), "case_id": case_id}


def handle_get_layer1_status(case_id: str) -> dict[str, Any]:
    try:
        checkpoint = r2_layer1_checkpoint(case_id)
        analyst = read_analyst_log(case_id)
        return {
            "checkpoint": checkpoint,
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
