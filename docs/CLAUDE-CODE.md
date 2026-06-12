# Claude Code setup (2026)

Run cold-box investigations through **Claude Code** with the project MCP server — the "mouth"
judges expect. Engine stays the same: read-only tools, audit chain, verifier, findings gate.

Official reference: [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp)

## Quick start

```bash
cd /opt/postmortem
bash scripts/setup-claude-code.sh

export EVIDENCE_ROOT=/evidence
export CASE_OUTPUT=/cases

claude   # in repo root — approve cold-box when prompted (/mcp)
```

First prompt example:

```
Investigate Ali Hadi Case #1. Use case_id ali-hadi-demo and evidence_case ali-hadi-1.
Run investigation_run with mode hybrid, from_cache /cases/ali-hadi-1/cache,
extracted_root /cases/ali-hadi-1/extracted. Then summarize findings and show self-correction
lines from progress.jsonl.
```

## What gets wired

| File | Purpose |
|------|---------|
| `.mcp.json` | **Project-scoped** MCP config (commit to git; team-shared) |
| `bin/cold-box-mcp-stdio` | Stdio launcher — activates venv, sets SIFT env paths |
| `CLAUDE.md` | Project instructions Claude Code reads automatically |
| `skills/` | Investigator methodology (read-only guidance) |

`.mcp.json` uses `${CLAUDE_PROJECT_DIR}` and `${EVIDENCE_ROOT:-/evidence}` per Anthropic's
[env expansion rules](https://code.claude.com/docs/en/mcp#environment-variable-expansion-in-mcpjson).

## Approve the server

Project-scoped servers require **one-time approval** per clone:

1. Start `claude` in the repo root.
2. Run **`/mcp`** — confirm **`cold-box`** is connected (stdio).
3. Approve if prompted.

If the server shows failed: use **absolute paths** — `bin/cold-box-mcp-stdio` resolves the repo
root itself; do not use relative paths in custom edits.

Debug: `claude --debug mcp` or see [Debug your configuration](https://code.claude.com/docs/en/debug-your-config).

## Alternative: CLI registration

If you prefer not to commit `.mcp.json`:

```bash
claude mcp add cold-box --scope project --transport stdio \
  -- "${CLAUDE_PROJECT_DIR}/bin/cold-box-mcp-stdio"
```

(`--scope project` writes `.mcp.json`; omit to use local scope in `~/.claude.json`.)

## MCP tools available

~**67 forensic tools** + meta tools:

- **`evidence_survey`** — start here
- **`tool_catalog`** — full parameter metadata
- **`investigation_run`** — one-shot hybrid/policy/llm agent loop → `findings.json` + `report.md`
- Memory, disk, registry, network, Linux, Android, macOS, YARA/exfil, etc.

There is **no** `execute_shell` on the wire (`tests/test_mcp_bypass.py`).

## Demo modes for judges

| Mode | What to show |
|------|----------------|
| **Hybrid one-shot** | `investigation_run(mode=hybrid)` on Ali Hadi or lab case |
| **Interactive MCP** | `evidence_survey` → several tools → audit trail → then `investigation_run` |
| **Policy accuracy** | `investigation_run(mode=policy)` — matches `docs/ACCURACY-REPORT.md` |

Scored benchmark numbers use **policy** brain. Live Claude Code demos should use **hybrid**.

## Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `EVIDENCE_ROOT` | `/evidence` | Read-only evidence tree |
| `CASE_OUTPUT` | `/cases` | Writable audits + reports |
| `VOL3` | `bin/vol` | Volatility 3 wrapper |
| `ANTHROPIC_API_KEY` | — | Required only for `mode=llm` or `hybrid` |

Load API key from repo `.env`: `source bin/load-agent-env` (never commit `.env`).

## Lab case (no external evidence)

```bash
export EVIDENCE_ROOT=/opt/postmortem/examples/sample-evidence
export CASE_OUTPUT=/tmp/cb-lab
```

Prompt:

```
Survey examples/sample-evidence with case_id lab-demo, then investigation_run
with evidence_case . and mode hybrid.
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `/mcp` shows 0 tools | Reconnect; run `claude --debug mcp`; ensure venv has `pip install -e .` |
| Server not listed | Restart Claude Code after editing `.mcp.json` |
| Volatility timeouts | Use `--from-cache` on Ali Hadi; raise tool timeouts on huge images |
| `investigation_run` needs API key | `source bin/load-agent-env` for hybrid/llm modes |
