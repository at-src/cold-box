"""Cold-box-room MCP server — Room A planning + R2 harness + Layer 1 logbook."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from cold_box_room.mcp.handlers import (
    handle_analyze_scratch,
    handle_apply_plan_a_step_status,
    handle_describe_sift_tool,
    handle_exit_layer1,
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

INSTRUCTIONS = """\
Cold-box-room — deterministic hallway: R1 → Room A → R2 → Room B → Room 3.

**Room A (extraction planning)** — case must be in room A:
- write_plan_a_md → formalize_plan_a → ready_for_room2.

**Room 2 (Layer 1 extraction)** — case must be in room 2:
- run_sift_tool / analyze_scratch → scratch + layer1_tool_log.md.
- apply_plan_a_step_status marks plan steps.
- submit_layer1_writeup promotes to Room B when gates pass.

**Room B (analysis planning)** — case must be in room B:
- read_layer1_tool_log / read_layer1_analyst_log first.
- write_plan_b_md → formalize_plan_b → ready_for_room3.

**Room 3** — analysis execution (not implemented yet).

You MUST NOT write to R1 staging. Tool output goes to case scratch only.
"""


def create_server() -> FastMCP:
    server = FastMCP("cold-box-room-mcp", instructions=INSTRUCTIONS)

    @server.tool()
    def list_sift_tools(category: str = "", runnable_only: bool = True) -> dict:
        """List SIFT tools from the catalog with stable tool_id."""
        return handle_list_sift_tools(category=category, runnable_only=runnable_only)

    @server.tool()
    def describe_sift_tool(tool_id: str) -> dict:
        """Full definition for one tool_id — input style, flags, verification."""
        return handle_describe_sift_tool(tool_id)

    @server.tool()
    def write_plan_a_md(case_id: str, markdown: str) -> dict:
        """Room A — save extraction plan markdown (steps + reasons; no SIFT tool ids)."""
        return handle_write_plan_a_md(case_id=case_id, markdown=markdown)

    @server.tool()
    def formalize_plan_a(case_id: str) -> dict:
        """Room A — validate plan_a.md and write plan_a.py checkbox file."""
        return handle_formalize_plan_a(case_id)

    @server.tool()
    def get_room_a_status(case_id: str) -> dict:
        """Room A checkpoint — formalized plan, ready_for_room2."""
        return handle_get_plan_a_status(case_id)

    @server.tool()
    def write_plan_b_md(case_id: str, markdown: str) -> dict:
        """Room B — save analysis plan markdown (steps + reasons; no skill ids)."""
        return handle_write_plan_b_md(case_id=case_id, markdown=markdown)

    @server.tool()
    def formalize_plan_b(case_id: str) -> dict:
        """Room B — validate plan_b.md and write plan_b.py checkbox file."""
        return handle_formalize_plan_b(case_id)

    @server.tool()
    def get_room_b_status(case_id: str) -> dict:
        """Room B checkpoint — formalized plan, ready_for_room3."""
        return handle_get_plan_b_status(case_id)

    @server.tool()
    def read_layer1_analyst_log(case_id: str) -> dict:
        """Read Layer 1 analyst write-up (findings, self-score, why)."""
        return handle_read_layer1_analyst_log(case_id)

    @server.tool()
    def apply_plan_a_step_status(
        case_id: str,
        step_id: int,
        status: str,
        audit_id: str = "",
        scratch_relpath: str = "",
        note: str = "",
    ) -> dict:
        """Room 2 — mark plan_a.py step passed/fail/not_relevant with proof."""
        proof: dict = {}
        if audit_id:
            proof["audit_id"] = audit_id
        if scratch_relpath:
            proof["scratch_relpath"] = scratch_relpath
            proof["exit_code"] = 0
        if note:
            proof["note"] = note
        return handle_apply_plan_a_step_status(
            case_id=case_id,
            step_id=step_id,
            status=status,
            proof=proof,
        )

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
        """Room 2 — run catalog tool against sandbox evidence; output to scratch."""
        return handle_run_sift_tool(
            tool_id=tool_id,
            case_id=case_id,
            input_relpath=input_relpath,
            purpose=purpose,
            why=why,
            extra_args=extra_args,
            timeout=timeout,
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
        """Room 2 — grep/strings/sqlite3/file on scratch output."""
        return handle_analyze_scratch(
            case_id=case_id,
            binary=binary,
            scratch_relpath=scratch_relpath,
            purpose=purpose,
            why=why,
            args=args,
            timeout=timeout,
        )

    @server.tool()
    def read_layer1_tool_log(case_id: str, limit: int = 20) -> dict:
        """Read harness tool log (layer1_tool_log.md + recent JSONL entries)."""
        return handle_read_layer1_tool_log(case_id, limit=limit)

    @server.tool()
    def get_layer1_status(case_id: str) -> dict:
        """Layer 1 promotion gates — extractions, analyst log, score, attempts."""
        return handle_get_layer1_status(case_id)

    @server.tool()
    def submit_layer1_writeup(
        case_id: str,
        findings: str,
        self_score: int,
        why: str,
    ) -> dict:
        """Room 2 analyst write-up; promotes to Room B when all gates pass."""
        return handle_submit_layer1_writeup(
            case_id=case_id,
            findings=findings,
            self_score=self_score,
            why=why,
        )

    @server.tool()
    def exit_layer1(case_id: str, reason: str) -> dict:
        """After 3 failed promotion attempts, document why score cannot exceed 8."""
        return handle_exit_layer1(case_id=case_id, reason=reason)

    return server
