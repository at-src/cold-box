"""Cold-box-room MCP server — SIFT harness + Layer 1 logbook."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from cold_box_room.mcp.handlers import (
    handle_analyze_scratch,
    handle_describe_sift_tool,
    handle_exit_layer1,
    handle_get_layer1_status,
    handle_list_sift_tools,
    handle_read_layer1_tool_log,
    handle_run_sift_tool,
    handle_submit_layer1_writeup,
)

INSTRUCTIONS = """\
Cold-box-room — R2 sandbox + SIFT tool harness + Layer 1 logbook.

Evidence is copied from sealed R1 staging into the R2 sandbox on promotion.
You MUST NOT write to R1 staging. Tool output goes to case scratch only.

Tools workflow:
1. list_sift_tools — browse catalog by tool_id (SIFT-###)
2. describe_sift_tool — flags, timeout, harness_usage, verification label
3. run_sift_tool — read sandbox evidence, write scratch + audit_id
4. analyze_scratch — grep/strings/sqlite3/file on scratch outputs

Layer 1 logbook (two files — do not mix):
- layer1_tool_log.md — harness fills automatically on every run_sift_tool / analyze_scratch
- layer1_analyst_log.md — YOU write findings + self_score + why via submit_layer1_writeup

Before Room 3:
- read_layer1_tool_log / get_layer1_status — see harness tool output and gate status
- submit_layer1_writeup — findings, self_score (1-10), why; promotes if score > 8 and ≥1 successful extraction
- exit_layer1 — after 3 failed promotion attempts, document why you cannot score above 8

Case must be in room 2 for tool runs and analyst write-up.
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
    def run_sift_tool(
        tool_id: str,
        case_id: str,
        input_relpath: str,
        purpose: str,
        why: str,
        extra_args: list[str] | None = None,
        timeout: int = 0,
    ) -> dict:
        """Run one catalog tool against R2 sandbox evidence; output to scratch."""
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
        """Run allowlisted parser (grep, strings, sqlite3, file, …) on scratch output."""
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
        """Agent Layer 1 write-up (findings + self_score + why). Promotes to R3 when gates pass."""
        return handle_submit_layer1_writeup(
            case_id=case_id,
            findings=findings,
            self_score=self_score,
            why=why,
        )

    @server.tool()
    def exit_layer1(case_id: str, reason: str) -> dict:
        """After 3 failed promotion attempts, document why score cannot exceed 8 and exit Layer 1."""
        return handle_exit_layer1(case_id=case_id, reason=reason)

    return server


def main() -> None:
    create_server().run()


if __name__ == "__main__":
    main()
