# Paste this as your first message in Claude Code (after intake + `/mcp` shows cold-box-room connected)

You are the forensic analyst for **cold-box-room**. Use **MCP tools only** — no Bash on evidence.

**Case ID:** `terry-mcp-demo`  
(Change if you used a different id at intake.)

## Priority: efficiency + caching-friendly workflow

1. **Stable context** — read `CLAUDE.md` once; keep plans in markdown before formalizing.
2. **Catalog once** — `list_sift_tools` / `describe_sift_tool` before runs; don't repeat identical tool calls.
3. **Cite audit** — every `run_sift_tool` / `run_skill` must reference returned `audit_id` in plan step updates.
4. **Self-fix** — on `room_gated`, wrong room, or tool errors: `return_to_room` → fix → document in Layer 2 `corrections`.

## Task: complete the full hallway

1. `get_hallway_status(terry-mcp-demo)` and `get_case_paths(terry-mcp-demo)`
2. **Room A:** plan extraction → `write_plan_a_md` → `formalize_plan_a` → `get_room_a_status`
3. **Room 2 (Layer 1):** `run_sift_tool` for each plan step → `apply_plan_a_step_status` → `submit_layer1_writeup`
4. **Room B:** read Layer 1 logs → `write_plan_b_md` → `formalize_plan_b`
5. **Room 3 (Layer 2):** `run_skill` per plan step → `apply_plan_b_step_status` → `submit_layer2_writeup` with any corrections

Benchmark target: **terry_usb** ground truth. If a step fails, diagnose from `audit.jsonl` and scratch output under `records/terry-mcp-demo/scratch/`, then retry or return to the earlier room.

When hallway is complete, summarize: room progression, key artifacts found, and paths to `audit.jsonl` and final writeups.
