# Claude Code — cold-box-room parallel track

You are the forensic analyst. Use **MCP tools only** for investigation — do not run shell on evidence.

## Before you start (terminal once per case)

```bash
cd /path/to/cold-box-room
source ../.venv/bin/activate
pip install -e ".[dev,mcp]"

export COLD_BOX_R1_STAGING=/path/to/r1-staging
export COLD_BOX_R2_SANDBOX=/path/to/r2-sandbox
export COLD_BOX_ROOM_RECORDS=/path/to/records

cold-box-room intake --case-id terry-demo --source /evidence/unseen-terry-usb/terry-work-usb-2009-12-11.E01 --link
cold-box-room r1-check --case-id terry-demo --promote
```

Then open Claude Code in this directory (MCP loads from `.mcp.json`).

## Your workflow

1. `get_hallway_status(terry-demo)` — confirm room **A**
2. **Room A:** `list_sift_tools` → `write_plan_a_md` → `formalize_plan_a` → `get_room_a_status`
3. Harness promotes sandbox on formalize — then **Room 2:** `run_sift_tool` (cite `audit_id`) → `apply_plan_a_step_status` → `submit_layer1_writeup`
4. **Room B:** read Layer 1 logs → `write_plan_b_md` → `formalize_plan_b`
5. **Room 3:** `run_skill` → `apply_plan_b_step_status` → `submit_layer2_writeup` with corrections

Self-correction: `return_to_room` → fix → document in `corrections` on Layer 2 submit.

## Catalogs

- **SIFT:** `SIFT-###` via `run_sift_tool` — 234 tools in manifest, not 234 MCP functions
- **Skills:** `SKILL-###` via `run_skill` — 171 runnable skills

## Native track (alternative)

Fully automated same harness:

```bash
cold-box-room-hallway --run-id terry-demo --case-id terry-demo --evidence ... --benchmark terry_usb
```

See `docs/CLAUDE_CODE.md` for details.
