"""Tool schemas and dispatch for the cold-box-room agent."""

from __future__ import annotations

import json
from typing import Any

from cold_box_room.mcp.handlers import (
    handle_analyze_scratch,
    handle_apply_plan_a_step_status,
    handle_describe_sift_tool,
    handle_extend_plan_a_step,
    handle_formalize_plan_a,
    handle_formalize_plan_b,
    handle_get_layer1_status,
    handle_get_plan_a_status,
    handle_get_plan_b_status,
    handle_list_sift_tools,
    handle_read_layer1_analyst_log,
    handle_read_layer1_tool_log,
    handle_run_sift_tool,
    handle_submit_layer1_writeup,
    handle_write_plan_a_md,
    handle_write_plan_b_md,
)
from cold_box_room.planning.guard import PlanningRoomGuardError, assert_tool_allowed_in_room
from cold_box_room.r1.hallway import current_room
from cold_box_room.r2.sandbox import list_sandbox_files, r2_status

ROOM_A_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_sift_tools",
        "description": "Browse SIFT tool catalog by tool_id (SIFT-###) — review before planning.",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "default": ""},
                "runnable_only": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "describe_sift_tool",
        "description": "Full tool definition including harness_usage and verification.",
        "input_schema": {
            "type": "object",
            "properties": {"tool_id": {"type": "string"}},
            "required": ["tool_id"],
        },
    },
    {
        "name": "write_plan_a_md",
        "description": (
            "Save extraction plan markdown (## Step N — title + **Reason:** only). "
            "No SIFT tool ids — tool choice is Room 2."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "markdown": {"type": "string"},
            },
            "required": ["case_id", "markdown"],
        },
    },
    {
        "name": "formalize_plan_a",
        "description": (
            "Typewriter step — read plan_a.md from disk, validate format, write plan_a.py checkbox file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "get_room_a_status",
        "description": "Room A checkpoint: plan formalized, ready_for_room2.",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
]

ROOM_B_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "read_layer1_tool_log",
        "description": "Read Layer 1 harness tool log (recent extractions + scratch refs).",
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["case_id"],
        },
    },
    {
        "name": "read_layer1_analyst_log",
        "description": "Read Layer 1 analyst write-up (findings, self-score, why).",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "get_layer1_status",
        "description": "Layer 1 summary — extraction count, plan_a gate, analyst log completeness.",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "list_sift_tools",
        "description": "Browse tool catalog (interim until skills catalog ships in Room 3).",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "default": ""},
                "runnable_only": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "describe_sift_tool",
        "description": "Full tool definition including harness_usage and verification.",
        "input_schema": {
            "type": "object",
            "properties": {"tool_id": {"type": "string"}},
            "required": ["tool_id"],
        },
    },
    {
        "name": "write_plan_b_md",
        "description": (
            "Save analysis plan markdown (## Step N — title + **Reason:** only). "
            "No skill script ids — tool choice is Room 3."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "markdown": {"type": "string"},
            },
            "required": ["case_id", "markdown"],
        },
    },
    {
        "name": "formalize_plan_b",
        "description": (
            "Typewriter step — read plan_b.md from disk, validate format, write plan_b.py checkbox file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "get_room_b_status",
        "description": "Room B checkpoint: plan formalized, ready_for_room3.",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
]

LAYER1_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_sandbox_files",
        "description": "List files in the R2 sandbox (available in Room 2 only, after Room A gate).",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "list_sift_tools",
        "description": "Browse SIFT tool catalog by tool_id (SIFT-###).",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "default": ""},
                "runnable_only": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "describe_sift_tool",
        "description": "Full tool definition including harness_usage and verification.",
        "input_schema": {
            "type": "object",
            "properties": {"tool_id": {"type": "string"}},
            "required": ["tool_id"],
        },
    },
    {
        "name": "run_sift_tool",
        "description": "Run catalog tool on sandbox evidence; output goes to scratch + tool log.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tool_id": {"type": "string"},
                "case_id": {"type": "string"},
                "input_relpath": {"type": "string"},
                "purpose": {"type": "string"},
                "why": {"type": "string"},
                "extra_args": {"type": "array", "items": {"type": "string"}},
                "timeout": {"type": "integer", "default": 0},
            },
            "required": ["tool_id", "case_id", "input_relpath", "purpose", "why"],
        },
    },
    {
        "name": "analyze_scratch",
        "description": "Run grep/strings/sqlite3/file on a scratch file from a prior run.",
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "binary": {"type": "string"},
                "scratch_relpath": {"type": "string"},
                "purpose": {"type": "string"},
                "why": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "timeout": {"type": "integer", "default": 0},
            },
            "required": ["case_id", "binary", "scratch_relpath", "purpose", "why"],
        },
    },
    {
        "name": "extend_plan_a_step",
        "description": (
            "Append a new pending checkpoint to plan_a.py during R2 when evidence needs more extraction. "
            "Same +1/-1 scoring rules as original plan steps."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "title": {"type": "string"},
                "reason": {"type": "string"},
                "tool_id": {"type": "string", "default": ""},
            },
            "required": ["case_id", "title", "reason"],
        },
    },
    {
        "name": "apply_plan_a_step_status",
        "description": (
            "Mark a plan_a.py step after working it: passed (+1, needs audit_id + scratch proof), "
            "fail (-1, needs note), not_relevant (0, drops from score pool, needs note). "
            "All steps must be resolved before submit; plan score must be ≥ 70%."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "step_id": {"type": "integer"},
                "status": {
                    "type": "string",
                    "enum": ["passed", "fail", "not_relevant", "held_for_later"],
                },
                "audit_id": {"type": "string", "default": ""},
                "scratch_relpath": {"type": "string", "default": ""},
                "note": {"type": "string", "default": ""},
            },
            "required": ["case_id", "step_id", "status"],
        },
    },
    {
        "name": "get_plan_a_status",
        "description": "Read plan_a.py checkpoint rows and formalization status.",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "read_layer1_tool_log",
        "description": "Read harness tool log (layer1_tool_log.md + recent entries).",
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["case_id"],
        },
    },
    {
        "name": "read_layer1_analyst_log",
        "description": "Read Layer 1 analyst write-up (findings, self-score, why).",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "get_layer1_status",
        "description": (
            "Layer 1 R2→Room B checkpoint: plan resolved + score ≥ 70%, successful_extractions, "
            "analyst log, self_score > 8, ready_for_room_b, blocked_reasons."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "submit_layer1_writeup",
        "description": (
            "Submit Layer 1 analyst write-up (findings + self_score + why). "
            "Requires all plan steps resolved, plan score ≥ 70%, self_score > 8 (9 or 10). "
            "On success, harness promotes case to Room B."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "findings": {"type": "string"},
                "self_score": {
                    "type": "integer",
                    "description": "Layer 1 self-rating 1–10 (not 0–100). Must be 9 or 10 to promote.",
                },
                "why": {"type": "string"},
            },
            "required": ["case_id", "findings", "self_score", "why"],
        },
    },
]

TOOL_SCHEMAS = LAYER1_TOOL_SCHEMAS


def _guard_tool(case_id: str, name: str) -> None:
    if not case_id:
        return
    try:
        room = current_room(case_id)
    except Exception:
        return
    assert_tool_allowed_in_room(tool_name=name, room=room)


def dispatch_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    case_id = str(args.get("case_id") or "")
    if case_id:
        try:
            _guard_tool(case_id, name)
        except PlanningRoomGuardError as exc:
            return {"ok": False, "error": str(exc), "case_id": case_id}

    if name == "list_sandbox_files":
        return {
            "case_id": case_id,
            "room": current_room(case_id),
            "files": list_sandbox_files(case_id),
            "status": r2_status(case_id),
        }
    if name == "list_sift_tools":
        return handle_list_sift_tools(
            category=str(args.get("category") or ""),
            runnable_only=bool(args.get("runnable_only", True)),
        )
    if name == "describe_sift_tool":
        return handle_describe_sift_tool(str(args["tool_id"]))
    if name == "write_plan_a_md":
        return handle_write_plan_a_md(
            case_id=case_id,
            markdown=str(args["markdown"]),
        )
    if name == "formalize_plan_a":
        return handle_formalize_plan_a(case_id)
    if name == "get_room_a_status":
        return handle_get_plan_a_status(case_id)
    if name == "write_plan_b_md":
        return handle_write_plan_b_md(
            case_id=case_id,
            markdown=str(args["markdown"]),
        )
    if name == "formalize_plan_b":
        return handle_formalize_plan_b(case_id)
    if name == "get_room_b_status":
        return handle_get_plan_b_status(case_id)
    if name == "read_layer1_analyst_log":
        return handle_read_layer1_analyst_log(case_id)
    if name == "extend_plan_a_step":
        return handle_extend_plan_a_step(
            case_id=case_id,
            title=str(args["title"]),
            reason=str(args["reason"]),
            tool_id=str(args.get("tool_id") or ""),
        )
    if name == "get_plan_a_status":
        return handle_get_plan_a_status(case_id)
    if name == "apply_plan_a_step_status":
        proof: dict[str, Any] = {}
        if args.get("audit_id"):
            proof["audit_id"] = str(args["audit_id"])
        if args.get("scratch_relpath"):
            proof["scratch_relpath"] = str(args["scratch_relpath"])
            proof["exit_code"] = 0
        if args.get("note"):
            proof["note"] = str(args["note"])
        return handle_apply_plan_a_step_status(
            case_id=case_id,
            step_id=int(args["step_id"]),
            status=str(args["status"]),
            proof=proof,
        )
    if name == "run_sift_tool":
        return handle_run_sift_tool(
            tool_id=str(args["tool_id"]),
            case_id=case_id,
            input_relpath=str(args["input_relpath"]),
            purpose=str(args["purpose"]),
            why=str(args["why"]),
            extra_args=list(args.get("extra_args") or []),
            timeout=int(args.get("timeout") or 0),
        )
    if name == "analyze_scratch":
        return handle_analyze_scratch(
            case_id=case_id,
            binary=str(args["binary"]),
            scratch_relpath=str(args["scratch_relpath"]),
            purpose=str(args["purpose"]),
            why=str(args["why"]),
            args=list(args.get("args") or []),
            timeout=int(args.get("timeout") or 0),
        )
    if name == "read_layer1_tool_log":
        return handle_read_layer1_tool_log(
            case_id,
            limit=int(args.get("limit") or 20),
        )
    if name == "get_layer1_status":
        return handle_get_layer1_status(case_id)
    if name == "submit_layer1_writeup":
        from cold_box_room.r2.analyst_log import normalize_self_score

        return handle_submit_layer1_writeup(
            case_id=case_id,
            findings=str(args["findings"]),
            self_score=normalize_self_score(args["self_score"]),
            why=str(args["why"]),
        )
    return {"ok": False, "error": f"Unknown tool: {name}"}


def tool_result_json(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False)[:12000]
