"""Register the full harness tool surface on FastMCP (Claude Code parallel track)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

from cold_box_room.agent.tools import dispatch_tool
from cold_box_room.mcp.kitchen import handle_get_case_paths, handle_get_hallway_status

_SUMMARY_KEYS = (
    "ok", "audit_id", "run_id", "outcome", "promoted", "complete",
    "ready_for_room2", "ready_for_room3", "gate_open", "error", "step_id", "room",
)
_STRIP_LARGE = {"markdown"}


def _log_mcp_event(tool_name: str, args: dict, result: dict) -> None:
    case_id = str(args.get("case_id") or "")
    if not case_id:
        return
    try:
        from cold_box_room.r1.paths import case_records_dir

        logged_input = {k: v for k, v in args.items() if k not in _STRIP_LARGE}
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "tool",
            "source": "mcp",
            "tool": tool_name,
            "input": logged_input,
            "output_summary": {k: result.get(k) for k in _SUMMARY_KEYS if k in result},
        }
        path = case_records_dir(case_id) / "AGENT_RUN.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _dispatch_logging(tool_name: str, args: dict) -> dict:
    result = dispatch_tool(tool_name, args)
    _log_mcp_event(tool_name, args, result)
    return result


def _register_kitchen_tools(server: FastMCP) -> None:
    @server.tool()
    def get_hallway_status(case_id: str) -> dict:
        """Current hallway room, seal state, unlocked rooms, staged files."""
        result = handle_get_hallway_status(case_id)
        _log_mcp_event("get_hallway_status", {"case_id": case_id}, result)
        return result

    @server.tool()
    def get_case_paths(case_id: str) -> dict:
        """Case directories, audit.jsonl path, and env root locations."""
        result = handle_get_case_paths(case_id)
        _log_mcp_event("get_case_paths", {"case_id": case_id}, result)
        return result


def _register_harness_tools(server: FastMCP) -> None:
    @server.tool()
    def list_sift_tools(category: str = "", runnable_only: bool = True) -> dict:
        """Browse SIFT catalog (234 tools by tool_id SIFT-###)."""
        return _dispatch_logging(
            "list_sift_tools",
            {"category": category, "runnable_only": runnable_only},
        )

    @server.tool()
    def describe_sift_tool(tool_id: str) -> dict:
        """Full SIFT tool definition before running."""
        return _dispatch_logging("describe_sift_tool", {"tool_id": tool_id})

    @server.tool()
    def list_skills(
        category: str = "",
        tag: str = "",
        agent_catalog_only: bool = True,
    ) -> dict:
        """Browse runnable skill catalog (SKILL-###)."""
        return _dispatch_logging(
            "list_skills",
            {
                "category": category,
                "tag": tag,
                "agent_catalog_only": agent_catalog_only,
            },
        )

    @server.tool()
    def describe_skill(skill_id: str) -> dict:
        """Load one skill contract and playbook text."""
        return _dispatch_logging("describe_skill", {"skill_id": skill_id})

    @server.tool()
    def list_unlocked_rooms(case_id: str) -> dict:
        """Rooms this case may return to (A, 2, B, 3 — never Room 1)."""
        return _dispatch_logging("list_unlocked_rooms", {"case_id": case_id})

    @server.tool()
    def return_to_room(case_id: str, room: str, reason: str) -> dict:
        """Self-correction — revisit an earlier room to fix a mistake."""
        return _dispatch_logging(
            "return_to_room",
            {"case_id": case_id, "room": room, "reason": reason},
        )

    @server.tool()
    def list_sandbox_files(case_id: str) -> dict:
        """List evidence files in the R2 sandbox copy."""
        return _dispatch_logging("list_sandbox_files", {"case_id": case_id})

    @server.tool()
    def write_plan_a_md(case_id: str, markdown: str) -> dict:
        """Room A — save extraction plan markdown."""
        return _dispatch_logging("write_plan_a_md", {"case_id": case_id, "markdown": markdown})

    @server.tool()
    def formalize_plan_a(case_id: str) -> dict:
        """Room A — validate plan_a.md and write plan_a.py."""
        return _dispatch_logging("formalize_plan_a", {"case_id": case_id})

    @server.tool()
    def get_room_a_status(case_id: str) -> dict:
        """Room A checkpoint — ready_for_room2."""
        return _dispatch_logging("get_room_a_status", {"case_id": case_id})

    @server.tool()
    def write_plan_b_md(case_id: str, markdown: str) -> dict:
        """Room B — save analysis plan markdown."""
        return _dispatch_logging("write_plan_b_md", {"case_id": case_id, "markdown": markdown})

    @server.tool()
    def formalize_plan_b(case_id: str) -> dict:
        """Room B — validate plan_b.md and write plan_b.py."""
        return _dispatch_logging("formalize_plan_b", {"case_id": case_id})

    @server.tool()
    def get_room_b_status(case_id: str) -> dict:
        """Room B checkpoint — ready_for_room3."""
        return _dispatch_logging("get_room_b_status", {"case_id": case_id})

    @server.tool()
    def run_sift_tool(
        tool_id: str,
        case_id: str,
        input_relpath: str,
        purpose: str,
        why: str,
        extra_args: list[str] | None = None,
        timeout: int = 0,
    ) -> dict:
        """Room 2 — run one catalog SIFT tool; output to scratch + audit.jsonl."""
        return _dispatch_logging(
            "run_sift_tool",
            {
                "tool_id": tool_id,
                "case_id": case_id,
                "input_relpath": input_relpath,
                "purpose": purpose,
                "why": why,
                "extra_args": extra_args or [],
                "timeout": timeout,
            },
        )

    @server.tool()
    def analyze_scratch(
        case_id: str,
        binary: str,
        scratch_relpath: str,
        purpose: str,
        why: str,
        args: list[str] | None = None,
        timeout: int = 0,
    ) -> dict:
        """Run grep/strings/sqlite3/file on harness scratch output."""
        return _dispatch_logging(
            "analyze_scratch",
            {
                "case_id": case_id,
                "binary": binary,
                "scratch_relpath": scratch_relpath,
                "purpose": purpose,
                "why": why,
                "args": args or [],
                "timeout": timeout,
            },
        )

    @server.tool()
    def extend_plan_a_step(
        case_id: str,
        title: str,
        reason: str,
        tool_id: str = "",
    ) -> dict:
        """Room 2 — append a plan_a.py step when more extraction is needed."""
        return _dispatch_logging(
            "extend_plan_a_step",
            {
                "case_id": case_id,
                "title": title,
                "reason": reason,
                "tool_id": tool_id,
            },
        )

    @server.tool()
    def apply_plan_a_step_status(
        case_id: str,
        step_id: int,
        status: str,
        audit_id: str = "",
        scratch_relpath: str = "",
        note: str = "",
    ) -> dict:
        """Room 2 — mark plan_a step passed/fail/not_relevant with proof."""
        return _dispatch_logging(
            "apply_plan_a_step_status",
            {
                "case_id": case_id,
                "step_id": step_id,
                "status": status,
                "audit_id": audit_id,
                "scratch_relpath": scratch_relpath,
                "note": note,
            },
        )

    @server.tool()
    def get_plan_a_status(case_id: str) -> dict:
        """Read plan_a.py checkpoint rows."""
        return _dispatch_logging("get_plan_a_status", {"case_id": case_id})

    @server.tool()
    def read_layer1_tool_log(case_id: str, limit: int = 20) -> dict:
        """Harness Layer 1 tool log."""
        return _dispatch_logging(
            "read_layer1_tool_log",
            {"case_id": case_id, "limit": limit},
        )

    @server.tool()
    def read_layer1_analyst_log(case_id: str) -> dict:
        """Layer 1 analyst write-up."""
        return _dispatch_logging("read_layer1_analyst_log", {"case_id": case_id})

    @server.tool()
    def get_layer1_status(case_id: str) -> dict:
        """Layer 1 promotion gates toward Room B."""
        return _dispatch_logging("get_layer1_status", {"case_id": case_id})

    @server.tool()
    def submit_layer1_writeup(
        case_id: str,
        findings: str,
        self_score: int,
        why: str,
    ) -> dict:
        """Room 2 — submit Layer 1 write-up; promotes to Room B when gates pass."""
        return _dispatch_logging(
            "submit_layer1_writeup",
            {
                "case_id": case_id,
                "findings": findings,
                "self_score": self_score,
                "why": why,
            },
        )

    @server.tool()
    def run_skill(
        skill_id: str,
        case_id: str,
        input_relpath: str,
        purpose: str = "",
        why: str = "",
        journal_id: str = "",
        script_args: list[str] | None = None,
        plan_step_id: int = 0,
    ) -> dict:
        """Room 3 — run one skill script through the harness."""
        args: dict[str, Any] = {
            "skill_id": skill_id,
            "case_id": case_id,
            "input_relpath": input_relpath,
            "purpose": purpose,
            "why": why,
            "journal_id": journal_id,
            "script_args": script_args or [],
        }
        if plan_step_id:
            args["plan_step_id"] = plan_step_id
        return _dispatch_logging("run_skill", args)

    @server.tool()
    def read_layer2_skill_log(case_id: str, limit: int = 20) -> dict:
        """Layer 2 skill execution log."""
        return _dispatch_logging(
            "read_layer2_skill_log",
            {"case_id": case_id, "limit": limit},
        )

    @server.tool()
    def read_layer2_tool_log(case_id: str, limit: int = 20) -> dict:
        """Layer 2 nested SIFT/scratch log from skill scripts."""
        return _dispatch_logging(
            "read_layer2_tool_log",
            {"case_id": case_id, "limit": limit},
        )

    @server.tool()
    def read_layer2_analyst_log(case_id: str) -> dict:
        """Layer 2 analyst write-up draft or submitted content."""
        return _dispatch_logging("read_layer2_analyst_log", {"case_id": case_id})

    @server.tool()
    def get_plan_b_status(case_id: str) -> dict:
        """Read plan_b.py checkpoint rows."""
        return _dispatch_logging("get_plan_b_status", {"case_id": case_id})

    @server.tool()
    def apply_plan_b_step_status(
        case_id: str,
        step_id: int,
        status: str,
        run_id: str = "",
        audit_id: str = "",
        note: str = "",
    ) -> dict:
        """Room 3 — mark plan_b step with skill run_id or audit_id proof."""
        return _dispatch_logging(
            "apply_plan_b_step_status",
            {
                "case_id": case_id,
                "step_id": step_id,
                "status": status,
                "run_id": run_id,
                "audit_id": audit_id,
                "note": note,
            },
        )

    @server.tool()
    def extend_plan_b_step(
        case_id: str,
        title: str,
        reason: str,
        tool_id: str = "",
    ) -> dict:
        """Room 3 — append a plan_b.py step."""
        return _dispatch_logging(
            "extend_plan_b_step",
            {
                "case_id": case_id,
                "title": title,
                "reason": reason,
                "tool_id": tool_id,
            },
        )

    @server.tool()
    def get_room3_status(case_id: str) -> dict:
        """Room 3 completion gates."""
        return _dispatch_logging("get_room3_status", {"case_id": case_id})

    @server.tool()
    def submit_layer2_writeup(
        case_id: str,
        findings: str,
        self_score: int,
        why: str,
        corrections: str,
    ) -> dict:
        """Room 3 — final analysis write-up; completes the case when gates pass."""
        return _dispatch_logging(
            "submit_layer2_writeup",
            {
                "case_id": case_id,
                "findings": findings,
                "self_score": self_score,
                "why": why,
                "corrections": corrections,
            },
        )

    @server.tool()
    def exit_layer2(case_id: str, reason: str) -> dict:
        """Exit Room 3 after three failed Layer 2 submit attempts."""
        return _dispatch_logging("exit_layer2", {"case_id": case_id, "reason": reason})


def register_all_tools(server: FastMCP) -> None:
    _register_kitchen_tools(server)
    _register_harness_tools(server)
