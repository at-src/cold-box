# CLAUDE.md — Claude Code guide for cold-box

> Read this before investigating. Guardrails are **architectural** (read-only MCP, audit chain,
> verifier gate) — not prompt-only.

## What this project is

**cold-box** is an autonomous DFIR investigator for dead hosts (disk + memory). Claude Code is the
**operator UI** ("the mouth"); typed MCP tools + a Python verifier are the engine.

```
Claude Code  →  cold-box MCP (~67 tools)  →  EVIDENCE_ROOT (read-only)
                    ↓
              audit.jsonl (SHA-256 chain)
                    ↓
         investigation_run OR manual tool loop
                    ↓
         verifier R1–R33  →  findings.json  →  report.md
```

Official MCP wiring: **`.mcp.json`** at repo root (project scope). Setup: `bash scripts/setup-claude-code.sh`
and `docs/CLAUDE-CODE.md`.

## Environment (set before starting Claude Code)

```bash
export EVIDENCE_ROOT=/evidence          # read-only case data
export CASE_OUTPUT=/cases               # audits, scratch, reports
cd /opt/postmortem && source .venv/bin/activate
pip install -e ".[dev]"                 # once
```

Lab / CI: `EVIDENCE_ROOT=examples/sample-evidence`, `CASE_OUTPUT=/tmp/cb-cases`.

## How to investigate (two modes)

### Mode A — Full pipeline (recommended for judges / demo video)

Call the **`investigation_run`** MCP tool (or ask Claude to run it):

| Parameter | Example |
|-----------|---------|
| `case_id` | `ali-hadi-demo` |
| `evidence_case` | `ali-hadi-1` |
| `mode` | `hybrid` (coverage floor + your ordering) |
| `from_cache` | `/cases/ali-hadi-1/cache` (hero case) |
| `extracted_root` | `/cases/ali-hadi-1/extracted` |

Outputs: `CASE_OUTPUT/<case_id>/findings.json`, `report.md`, `progress.jsonl`, `audit.jsonl`.

For scored accuracy claims use **`mode=policy`**. For live demo narrative use **`mode=hybrid`**.

### Mode B — Interactive MCP (show tool-by-tool reasoning)

1. **`evidence_survey`** — always first; pass `case_id` + `case_relpath`.
2. **`tool_catalog`** — if you need parameter hints.
3. Run typed tools based on survey kinds (memory → disk → registry → platform).
4. Finish with **`investigation_run`** in `hybrid` mode **or** tell the user to review `audit.jsonl`.

Every tool requires **`case_id`** (your run id under `CASE_OUTPUT`) and paths **relative to `EVIDENCE_ROOT`**.

## Non-negotiables

1. **Evidence is read-only** — no shell, write, or mount tools exist on the MCP wire.
2. **Every MCP call returns `audit_id`** — cite audit IDs in findings; do not invent evidence.
3. **Verifier is deterministic Python** — not LLM opinion. Contradictions mean investigate further.
4. **Self-correction** — when new verifier signals appear, update hypothesis; log should contain `self-correction` in `progress.jsonl`.

## Hero demo cases

| Case | `evidence_case` | Notes |
|------|-----------------|-------|
| Lab synthetic | `.` under `examples/sample-evidence` | Fast CI case |
| Ali Hadi #1 | `ali-hadi-1` | Web + memory; cache + extracted disk required |
| Nitroba | `nitroba` | PCAP-only network case |
| NIST hacking | `nist-hacking` | Raw split image; needs `disk_extract_image` first |

Prep Ali Hadi: `bash scripts/cache_ali_hadi_memory.sh` and `bash scripts/extract_ali_hadi_disk.sh`.

## Skills (methodology)

- `skills/dead-host-investigation/SKILL.md` — phase flow
- `skills/memory-forensics/SKILL.md` — Vol3 triage
- `skills/windows-artifacts/SKILL.md` — prefetch/MFT/registry

## CLI equivalents (if MCP is unavailable)

```bash
cold-box-agent run --case-id demo --evidence-case ali-hadi-1 --hybrid \
  --from-cache /cases/ali-hadi-1/cache \
  --extracted-root /cases/ali-hadi-1/extracted
cold-box-audit verify /cases/demo/audit.jsonl
```

## Verify MCP in Claude Code

After starting a session: run **`/mcp`** — approve project server **`cold-box`**. Debug: `claude --debug mcp`.

Docs: https://code.claude.com/docs/en/mcp
