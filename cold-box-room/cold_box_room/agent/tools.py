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
from cold_box_room.skills.executor import run_skill
from cold_box_room.skills.registry import describe_skill, list_skills_dict

SIFT_BROWSE_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_sift_tools",
        "description": (
            "Browse SIFT extraction tool catalog (SIFT-###) — reference only in Room 3. "
            "To run extraction, return_to_room to Room 2."
        ),
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
        "description": (
            "Full SIFT tool definition — browse only in Room 3; execution is Room 2 via return_to_room."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"tool_id": {"type": "string"}},
            "required": ["tool_id"],
        },
    },
]

SKILLS_BROWSE_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_skills",
        "description": (
            "Browse skill catalog by skill_id (SKILL-###). "
            "Default excludes partial and reference-only entries."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "default": ""},
                "tag": {"type": "string", "default": ""},
                "agent_catalog_only": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "describe_skill",
        "description": (
            "Full skill contract: inputs, outputs, proof rules, playbook text. "
            "suggested_tool_ids are hints only — skill does not run tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"skill_id": {"type": "string"}},
            "required": ["skill_id"],
        },
    },
]

REVISIT_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_unlocked_rooms",
        "description": (
            "List rooms this case may return to (A, 2, B, 3 — never Room 1; sealed evidence is locked)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "return_to_room",
        "description": (
            "Return to an earlier unlocked room to fix a mistake (Room A, 2, B, or 3 — not Room 1). "
            "State what was wrong in reason — required in submit_layer2_writeup corrections if you revisit."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "room": {
                    "type": "string",
                    "description": "Target room: 2, B, A, or 3.",
                },
                "reason": {
                    "type": "string",
                    "description": "What mistake you are fixing by going back.",
                },
            },
            "required": ["case_id", "room", "reason"],
        },
    },
]

ROOM_3_TOOL_SCHEMAS: list[dict[str, Any]] = [
    *SKILLS_BROWSE_SCHEMAS,
    *SIFT_BROWSE_SCHEMAS,
    *REVISIT_TOOL_SCHEMAS,
    {
        "name": "run_skill",
        "description": (
            "Run a ported skill script (library/*/scripts/agent.py) in Room 3. "
            "Always returns ok:true when the harness executed the request. "
            "Check outcome: success (mark plan step), failed (retry — skill still runnable), "
            "not_runnable (pick another skill). "
            "A failed row in layer2_skill_log is a failed attempt, not skill removal."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "case_id": {"type": "string"},
                "input_relpath": {
                    "type": "string",
                    "description": "Evidence file inside the R2 sandbox (e.g. disk.E01).",
                },
                "journal_id": {"type": "string", "default": ""},
                "script_args": {"type": "array", "items": {"type": "string"}, "default": []},
                "purpose": {"type": "string", "default": ""},
                "why": {"type": "string", "default": ""},
                "plan_step_id": {"type": "integer", "default": 0},
            },
            "required": ["skill_id", "case_id", "input_relpath"],
        },
    },
    {
        "name": "list_sandbox_files",
        "description": (
            "List files in the R2 sandbox (same evidence copy from Layer 1). "
            "Always returns ok: true when the listing succeeds. "
            "r2_status_state is 'available' in Room 2/3 or 'not_applicable' elsewhere — "
            "that is room gating, not tool unavailability."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "analyze_scratch",
        "description": "Run grep/strings/sqlite3/file on scratch from skill or extraction runs.",
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
        "name": "read_layer2_skill_log",
        "description": (
            "Read Layer 2 harness skill log (run_skill executions + audit ids). "
            "Use outcome (success/failed), not legacy ok alone. "
            "failed = retry the skill; only not_runnable from run_skill means pick another skill."
        ),
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
        "name": "read_layer2_tool_log",
        "description": (
            "Read Layer 2 harness tool log (nested SIFT/scratch from skill scripts). "
            "Harness-only — agent never edits this file."
        ),
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
        "name": "read_layer2_analyst_log",
        "description": "Read Layer 2 analyst write-up (findings, corrections, self-score, why).",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "get_plan_b_status",
        "description": "Read plan_b.py checkpoint rows and formalization status.",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "apply_plan_b_step_status",
        "description": (
            "Mark a plan_b.py step after run_skill: passed (+1, needs run_id or audit_id from skill log), "
            "fail (-1, needs note), not_relevant (0, needs note)."
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
                "run_id": {"type": "string", "default": ""},
                "audit_id": {"type": "string", "default": ""},
                "note": {"type": "string", "default": ""},
            },
            "required": ["case_id", "step_id", "status"],
        },
    },
    {
        "name": "extend_plan_b_step",
        "description": "Append a new pending checkpoint to plan_b.py during Room 3 if analysis needs another step.",
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
        "name": "get_room3_status",
        "description": "Room 3 checkpoint: plan_b resolved, skill runs, analyst log, ready_for_complete.",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "submit_layer2_writeup",
        "description": (
            "Submit Layer 2 analyst write-up (findings + self_score + why + corrections). "
            "Corrections must describe any mistake fixed via return_to_room, or 'none'. "
            "Requires plan_b resolved, score ≥ 70%, successful skill run, self_score > 8."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "findings": {"type": "string"},
                "self_score": {"type": "integer"},
                "why": {"type": "string"},
                "corrections": {"type": "string"},
            },
            "required": ["case_id", "findings", "self_score", "why", "corrections"],
        },
    },
    {
        "name": "exit_layer2",
        "description": (
            "Exit Layer 2 after 3 failed submit_layer2_writeup attempts. Case ends incomplete in Room 3."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["case_id", "reason"],
        },
    },
    {
        "name": "read_layer1_tool_log",
        "description": "Read Layer 1 harness tool log (extractions + scratch refs).",
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
        "description": "Layer 1 summary — extraction count and analyst log completeness.",
        "input_schema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
]

ROOM_A_TOOL_SCHEMAS: list[dict[str, Any]] = [
    *REVISIT_TOOL_SCHEMAS,
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
    *REVISIT_TOOL_SCHEMAS,
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
        "description": "Browse SIFT extraction tool catalog (Layer 1 reference while planning analysis).",
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
    *SKILLS_BROWSE_SCHEMAS,
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
    *REVISIT_TOOL_SCHEMAS,
    {
        "name": "list_sandbox_files",
        "description": (
            "List files in the R2 sandbox (same evidence copy from Layer 1). "
            "Always returns ok: true when the listing succeeds. "
            "r2_status_state is 'available' in Room 2/3 or 'not_applicable' elsewhere — "
            "that is room gating, not tool unavailability."
        ),
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
            return {
                "ok": True,
                "outcome": "room_gated",
                "error": str(exc),
                "case_id": case_id,
            }

    if name == "list_skills":
        rows = list_skills_dict(
            category=str(args.get("category") or "") or None,
            tag=str(args.get("tag") or "") or None,
            agent_catalog_only=bool(args.get("agent_catalog_only", True)),
        )
        return {
            "skills": rows,
            "count": len(rows),
            "reading_guide": (
                "Every skill listed here is agent-runnable. "
                "A failed prior run_skill attempt does not remove a skill — retry with fixed inputs."
            ),
        }
    if name == "describe_skill":
        return describe_skill(str(args["skill_id"]))
    if name == "run_skill":
        script_args = args.get("script_args") or []
        if not isinstance(script_args, list):
            script_args = []
        plan_step_id = args.get("plan_step_id")
        step_id: int | None = None
        if plan_step_id not in (None, "", 0):
            step_id = int(plan_step_id)
        return run_skill(
            skill_id=str(args["skill_id"]),
            case_id=case_id,
            input_relpath=str(args.get("input_relpath") or ""),
            journal_id=str(args.get("journal_id") or ""),
            script_args=[str(a) for a in script_args],
            purpose=str(args.get("purpose") or ""),
            why=str(args.get("why") or ""),
            plan_step_id=step_id,
        )
    if name == "list_unlocked_rooms":
        from cold_box_room.r1.hallway import list_room_revisits, unlocked_rooms

        return {
            "case_id": case_id,
            "room": current_room(case_id),
            "unlocked_rooms": sorted(unlocked_rooms(case_id)),
            "revisits": list_room_revisits(case_id),
        }
    if name == "return_to_room":
        from cold_box_room.r1.hallway import return_to_room

        try:
            return return_to_room(
                case_id,
                str(args["room"]),
                reason=str(args.get("reason") or ""),
            )
        except Exception as exc:
            return {"ok": False, "error": str(exc), "case_id": case_id}
    if name == "read_layer2_skill_log":
        from cold_box_room.room_3 import read_skill_log, room3_checkpoint

        log = read_skill_log(case_id, limit=int(args.get("limit") or 20))
        try:
            log["checkpoint"] = room3_checkpoint(case_id)
        except Exception as exc:
            log["checkpoint_error"] = str(exc)
        return log
    if name == "read_layer2_tool_log":
        from cold_box_room.room_3 import read_layer2_tool_log, room3_checkpoint

        log = read_layer2_tool_log(case_id, limit=int(args.get("limit") or 20))
        try:
            log["checkpoint"] = room3_checkpoint(case_id)
        except Exception as exc:
            log["checkpoint_error"] = str(exc)
        return log
    if name == "read_layer2_analyst_log":
        from cold_box_room.room_3 import read_analyst_log

        analyst = read_analyst_log(case_id)
        return {"ok": True, "case_id": case_id, "analyst_log": analyst}
    if name == "get_room3_status":
        from cold_box_room.room_3 import get_room3_status

        return get_room3_status(case_id)
    if name == "apply_plan_b_step_status":
        proof: dict[str, Any] = {}
        if args.get("run_id"):
            proof["run_id"] = str(args["run_id"])
        if args.get("audit_id"):
            proof["audit_id"] = str(args["audit_id"])
        if args.get("note"):
            proof["note"] = str(args["note"])
        from cold_box_room.room_3 import apply_plan_b_step_status

        return apply_plan_b_step_status(
            case_id=case_id,
            step_id=int(args["step_id"]),
            status=str(args["status"]),
            proof=proof,
        )
    if name == "extend_plan_b_step":
        from cold_box_room.room_3 import extend_plan_b_step

        return extend_plan_b_step(
            case_id=case_id,
            title=str(args["title"]),
            reason=str(args["reason"]),
            tool_id=str(args.get("tool_id") or ""),
        )
    if name == "submit_layer2_writeup":
        from cold_box_room.r2.analyst_log import normalize_self_score
        from cold_box_room.room_3 import submit_layer2_writeup

        try:
            score = normalize_self_score(args["self_score"])
        except Exception as exc:
            return {"ok": False, "error": str(exc), "case_id": case_id}
        return submit_layer2_writeup(
            case_id=case_id,
            findings=str(args["findings"]),
            self_score=score,
            why=str(args["why"]),
            corrections=str(args["corrections"]),
        )
    if name == "exit_layer2":
        from cold_box_room.room_3 import exit_layer2

        try:
            return exit_layer2(case_id=case_id, reason=str(args.get("reason") or ""))
        except Exception as exc:
            return {"ok": False, "error": str(exc), "case_id": case_id}
    if name == "list_sandbox_files":
        room = current_room(case_id)
        files = list_sandbox_files(case_id)
        payload: dict[str, Any] = {
            "ok": True,
            "case_id": case_id,
            "room": room,
            "files": files,
        }
        try:
            payload["r2_status"] = r2_status(case_id)
            payload["r2_status_state"] = "available"
        except Exception:
            payload["r2_status_state"] = "not_applicable"
            payload["r2_status_note"] = (
                "Sandbox file list succeeded. Full r2_status (materialized_at, "
                "non_empty_files) is only computed in Room 2 or Room 3 — not a tool failure."
            )
        return payload
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
