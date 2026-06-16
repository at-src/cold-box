# Claude Code parallel track

Cold-box-room supports **two agent hosts** on the **same harness**:

| Track | Host | Entry |
|-------|------|--------|
| **Native** | Python `agent/engine.py` + Anthropic API | `cold-box-room-hallway` |
| **Claude Code** | Claude Code session + MCP stdio | `cold-box-room-mcp` |

Both call `dispatch_tool()` → same room guards, catalogs, `audit.jsonl`, scratch rules.

## Why two tracks

- **Native:** CI, regression, unattended E2E (~16 min Terry, measured accuracy)
- **Claude Code:** Visible investigation for judges (Protocol SIFT preferred host), demo video, interactive self-correction

## Setup

```bash
cd cold-box-room
bash scripts/setup_claude_code.sh   # installs Claude Code + venv MCP; does not start a session
```

See **`docs/CLAUDE_CODE_SETUP.md`** for wrapper, monitor, and start prompt.

### Environment

| Variable | Purpose |
|----------|---------|
| `COLD_BOX_R1_STAGING` | Sealed evidence |
| `COLD_BOX_R2_SANDBOX` | Working copy |
| `COLD_BOX_ROOM_RECORDS` | Plans, logs, audit |
| `ANTHROPIC_API_KEY` | Native track only (Claude Code uses its own auth) |

### MCP config

Copy or symlink `.mcp.json` into your Claude Code project settings, or point Claude Code at `cold-box-room/.mcp.json`.

Adjust paths in `env` to your VM.

### Case intake (both tracks)

```bash
cold-box-room intake --case-id CASE --source /path/to/evidence.E01
cold-box-room r1-check --case-id CASE --promote
```

EWF E02–E04 auto-attach when passing a single E01.

## Claude Code investigation

1. Start MCP: `cold-box-room-mcp` (stdio — Claude Code launches it)
2. `get_hallway_status(case_id)`
3. Follow hallway per `CLAUDE.md`
4. Audit trail: `records/{case_id}/audit.jsonl`

## MCP tool surface (~30 typed tools)

Not 234+171 separate MCP functions. Catalogs are data:

- `list_sift_tools` / `describe_sift_tool` / `run_sift_tool`
- `list_skills` / `describe_skill` / `run_skill`
- Planning, logs, submit, `return_to_room`

Kitchen helpers (MCP-only): `get_hallway_status`, `get_case_paths`

## Verify MCP

```bash
cold-box-room-mcp   # blocks on stdio — Ctrl+C to exit
pytest tests/test_mcp_parallel.py -q
```

## Score after Claude Code run

```bash
python scripts/score_e2e_accuracy.py --case-id CASE --benchmark terry_usb
```

Same benchmarks as native track.
