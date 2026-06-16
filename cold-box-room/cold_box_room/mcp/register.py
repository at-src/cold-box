"""Register the full harness tool surface on FastMCP (Claude Code parallel track)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from cold_box_room.agent.tools import dispatch_tool
from cold_box_room.mcp.kitchen import handle_get_case_paths, handle_get_hallway_status


def _register_kitchen_tools(server: FastMCP) -> None:
    @server.tool()
    def get_hallway_status(case_id: str) -> dict:
        """Current hallway room, seal state, unlocked rooms, staged files."""
        return handle_get_hallway_status(case_id)

    @server.tool()
    def get_case_paths(case_id: str) -> dict:
        """Case directories, audit.jsonl path, and env root locations."""
        return handle_get_case_paths(case_id)


def _register_harness_tools(server: FastMCP) -> None:
    @server.tool()
    def list_sift_tools(category: str = "", runnable_only: bool = True) -> dict:
        """Browse SIFT catalog (234 tools by tool_id SIFT-###)."""
        return dispatch_tool(
            "list_sift_tools",
            {"category": category, "runnable_only": runnable_only},
        )

    @server.tool()
    def describe_sift_tool(tool_id: str) -> dict:
        """Full SIFT tool definition before running."""
        return dispatch_tool("describe_sift_tool", {"tool_id": tool_id})

    @server.tool()
    def list_skills(
        category: str = "",
        tag: str = "",
        agent_catalog_only: bool = True,
    ) -> dict:
        """Browse runnable skill catalog (SKILL-###)."""
        return dispatch_tool(
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
        return dispatch_tool("describe_skill", {"skill_id": skill_id})

    @server.tool()
    def list_unlocked_rooms(case_id: str) -> dict:
        """Rooms this case may return to (A, 2, B, 3 — never Room 1)."""
        return dispatch_tool("list_unlocked_rooms", {"case_id": case_id})

    @server.tool()
    def return_to_room(case_id: str, room: str, reason: str) -> dict:
        """Self-correction — revisit an earlier room to fix a mistake."""
        return dispatch_tool(
            "return_to_room",
            {"case_id": case_id, "room": room, "reason": reason},
        )

    @server.tool()
    def list_sandbox_files(case_id: str) -> dict:
        """List evidence files in the R2 sandbox copy."""
        return dispatch_tool("list_sandbox_files", {"case_id": case_id})

    @server.tool()
    def write_plan_a_md(case_id: str, markdown: str) -> dict:
        """Room A — save extraction plan markdown."""
        return dispatch_tool("write_plan_a_md", {"case_id": case_id, "markdown": markdown})

    @server.tool()
    def formalize_plan_a(case_id: str) -> dict:
        """Room A — validate plan_a.md and write plan_a.py."""
        return dispatch_tool("formalize_plan_a", {"case_id": case_id})

    @server.tool()
    def get_room_a_status(case_id: str) -> dict:
        """Room A checkpoint — ready_for_room2."""
        return dispatch_tool("get_room_a_status", {"case_id": case_id})

    @server.tool()
    def write_plan_b_md(case_id: str, markdown: str) -> dict:
        """Room B — save analysis plan markdown."""
        return dispatch_tool("write_plan_b_md", {"case_id": case_id, "markdown": markdown})

    @server.tool()
    def formalize_plan_b(case_id: str) -> dict:
        """Room B — validate plan_b.md and write plan_b.py."""
        return dispatch_tool("formalize_plan_b", {"case_id": case_id})

    @server.tool()
    def get_room_b_status(case_id: str) -> dict:
        """Room B checkpoint — ready_for_room3."""
        return dispatch_tool("get_room_b_status", {"case_id": case_id})

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
        return dispatch_tool(
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
        return dispatch_tool(
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
        return dispatch_tool(
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
        return dispatch_tool(
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
        return dispatch_tool("get_plan_a_status", {"case_id": case_id})

    @server.tool()
    def read_layer1_tool_log(case_id: str, limit: int = 20) -> dict:
        """Harness Layer 1 tool log."""
        return dispatch_tool(
            "read_layer1_tool_log",
            {"case_id": case_id, "limit": limit},
        )

    @server.tool()
    def read_layer1_analyst_log(case_id: str) -> dict:
        """Layer 1 analyst write-up."""
        return dispatch_tool("read_layer1_analyst_log", {"case_id": case_id})

    @server.tool()
    def get_layer1_status(case_id: str) -> dict:
        """Layer 1 promotion gates toward Room B."""
        return dispatch_tool("get_layer1_status", {"case_id": case_id})

    @server.tool()
    def submit_layer1_writeup(
        case_id: str,
        findings: str,
        self_score: int,
        why: str,
    ) -> dict:
        """Room 2 — submit Layer 1 write-up; promotes to Room B when gates pass."""
        return dispatch_tool(
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
        return dispatch_tool("run_skill", args)

    @server.tool()
    def read_layer2_skill_log(case_id: str, limit: int = 20) -> dict:
        """Layer 2 skill execution log."""
        return dispatch_tool(
            "read_layer2_skill_log",
            {"case_id": case_id, "limit": limit},
        )

    @server.tool()
    def read_layer2_tool_log(case_id: str, limit: int = 20) -> dict:
        """Layer 2 nested SIFT/scratch log from skill scripts."""
        return dispatch_tool(
            "read_layer2_tool_log",
            {"case_id": case_id, "limit": limit},
        )

    @server.tool()
    def read_layer2_analyst_log(case_id: str) -> dict:
        """Layer 2 analyst write-up draft or submitted content."""
        return dispatch_tool("read_layer2_analyst_log", {"case_id": case_id})

    @server.tool()
    def get_plan_b_status(case_id: str) -> dict:
        """Read plan_b.py checkpoint rows."""
        return dispatch_tool("get_plan_b_status", {"case_id": case_id})

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
        return dispatch_tool(
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
        return dispatch_tool(
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
        return dispatch_tool("get_room3_status", {"case_id": case_id})

    @server.tool()
    def submit_layer2_writeup(
        case_id: str,
        findings: str,
        self_score: int,
        why: str,
        corrections: str,
    ) -> dict:
        """Room 3 — final analysis write-up; completes the case when gates pass."""
        return dispatch_tool(
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
        return dispatch_tool("exit_layer2", {"case_id": case_id, "reason": reason})


def register_all_tools(server: FastMCP) -> None:
    _register_kitchen_tools(server)
    _register_harness_tools(server)
