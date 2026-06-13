"""Cold-box-room MCP server — four SIFT harness tools."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from cold_box_room.mcp.handlers import (
    handle_analyze_scratch,
    handle_describe_sift_tool,
    handle_list_sift_tools,
    handle_run_sift_tool,
)

INSTRUCTIONS = """\
Cold-box-room — R2 sandbox + SIFT tool harness.

Evidence is copied from sealed R1 staging into the R2 sandbox on promotion.
You MUST NOT write to R1 staging. Tool output goes to case scratch only.

Workflow:
1. list_sift_tools — browse catalog by tool_id (SIFT-###)
2. describe_sift_tool — flags, timeout, harness_usage, verification label
3. run_sift_tool — read sandbox evidence, write scratch + audit_id
4. analyze_scratch — grep/strings/sqlite3/file on scratch outputs

Case must be in room 2 (promoted from R1) before run_sift_tool or analyze_scratch.
Every run returns audit_id (CB-…) for citations.
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

    return server


def main() -> None:
    create_server().run()


if __name__ == "__main__":
    main()
