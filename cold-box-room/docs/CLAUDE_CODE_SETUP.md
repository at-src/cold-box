# Claude Code setup (parallel track)

Setup only — **do not start an investigation session until intake is done.**

## Quick setup

```bash
cd /opt/postmortem/cold-box-room
bash scripts/setup_claude_code.sh
```

This installs Claude Code (`~/.local/bin/claude`), ensures the venv has `[dev,mcp]`, and verifies `.mcp.json` + `.claude/settings.json`.

## What got wired

| Piece | Path | Purpose |
|-------|------|---------|
| Wrapper | `bin/claude-room` | Loads `.env`, `COLD_BOX_*`, venv PATH; `cd` into project |
| MCP server | `.mcp.json` | stdio → `cold-box-room-mcp` (same harness as native) |
| Permissions | `.claude/settings.json` | Auto-approve `mcp__cold-box-room__*`; block Bash on evidence |
| Monitor hook | `.claude/hooks/log-mcp-tool.sh` | Logs each MCP call to `records/{case}/claude_code_monitor.log` |
| Live monitor | `scripts/monitor_case.sh` | Tail audit/hallway + heartbeat every 15s |
| Start prompt | `docs/CLAUDE_CODE_START_PROMPT.md` | Paste when you're ready to run |

## Caching / cost

- **Claude Code** uses Anthropic prompt caching automatically on supported models (Sonnet 4.6). No extra env var needed in this track.
- **Native hallway** (`cold-box-room-hallway`) still uses `ANTHROPIC_PROMPT_CACHE=1` from `/opt/postmortem/.env`.
- Workflow tip for both tracks: call `list_sift_tools` / `describe_sift_tool` once per tool, keep plans in markdown, avoid repeating identical `run_sift_tool` calls — that keeps context stable and cheaper.

## Before Claude Code (every case)

```bash
cd /opt/postmortem/cold-box-room
source ../.venv/bin/activate

export COLD_BOX_R1_STAGING=/opt/postmortem/cold-box-room/r1-staging
export COLD_BOX_R2_SANDBOX=/opt/postmortem/cold-box-room/r2-sandbox
export COLD_BOX_ROOM_RECORDS=/opt/postmortem/cold-box-room/records

cold-box-room intake --case-id terry-mcp-demo --source /evidence/unseen-terry-usb/terry-work-usb-2009-12-11.E01 --link
cold-box-room r1-check --case-id terry-mcp-demo --promote
```

## Verify MCP (no session)

```bash
cd /opt/postmortem/cold-box-room
export PATH="$HOME/.local/bin:$PATH"
claude mcp list
claude doctor
pytest tests/test_mcp_parallel.py -q
```

Expect `cold-box-room` MCP server connected when run from this directory.

## When you're ready to run

**Terminal 1 — monitor:**

```bash
/opt/postmortem/cold-box-room/scripts/monitor_case.sh terry-mcp-demo
```

**Terminal 2 — Claude Code:**

```bash
/opt/postmortem/cold-box-room/bin/claude-room
```

Inside Claude Code:

1. `/mcp` — confirm `cold-box-room` is connected
2. Paste the prompt from `docs/CLAUDE_CODE_START_PROMPT.md`
3. Watch Terminal 1 for `audit.jsonl` / hallway room changes

## Score after run

```bash
python scripts/score_e2e_accuracy.py --case-id terry-mcp-demo --benchmark terry_usb
```

Same benchmarks as the native track.
