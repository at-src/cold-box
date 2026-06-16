"""Cold-box-room MCP server — Claude Code parallel track (stdio).

Uses the same harness dispatch as the native hallway agent. Does not replace
cold-box-room-hallway; both tracks share dispatch_tool(), audit.jsonl, and catalogs.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from cold_box_room.mcp.register import register_all_tools

INSTRUCTIONS = """\
Cold-box-room MCP — Protocol SIFT–compatible hallway harness for Claude Code.

You are the investigator. Use these MCP tools only — never shell on evidence.

## Setup (operator runs once in terminal, not via bash on evidence)
1. `cold-box-room intake --case-id CASE --source /path/to/image.E01 [--link]`
2. `cold-box-room r1-check --case-id CASE --promote`  → Room A
3. Set env if needed: COLD_BOX_R1_STAGING, COLD_BOX_R2_SANDBOX, COLD_BOX_ROOM_RECORDS

Then call `get_hallway_status(case_id)` and work the current room.

## Hallway (same as native agent)
Room 1 sealed → Room A plan → Room 2 SIFT → Room B plan → Room 3 skills → complete

- Room A: write_plan_a_md → formalize_plan_a → get_room_a_status (ready_for_room2)
- Room 2: run_sift_tool / analyze_scratch → apply_plan_a_step_status → submit_layer1_writeup
- Room B: read_layer1_* → write_plan_b_md → formalize_plan_b
- Room 3: run_skill → apply_plan_b_step_status → submit_layer2_writeup

Wrong-room tools return room_gated errors — use return_to_room to self-correct.

## Catalogs (not separate MCP tools)
- 234 SIFT tools: list_sift_tools → describe_sift_tool → run_sift_tool(tool_id=SIFT-###)
- 171 skills: list_skills → describe_skill → run_skill(skill_id=SKILL-###)

## Proof
Every run_sift_tool returns audit_id. Cite audit_id in findings. Trace: audit.jsonl → scratch/.

Room 1 is locked forever — no return_to_room to Room 1.
"""


def create_server() -> FastMCP:
    server = FastMCP("cold-box-room-mcp", instructions=INSTRUCTIONS)
    register_all_tools(server)
    return server


def main() -> None:
    create_server().run()


if __name__ == "__main__":
    main()
