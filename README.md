# cold-box

Autonomous DFIR investigator for the SANS FIND EVIL! hackathon.

## Requirements

- Python 3.10+
- SIFT Workstation (or compatible forensics toolchain on Linux)

## Install (development)

```bash
git clone https://github.com/at-src/cold-box.git
cd cold-box
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Environment

```bash
export EVIDENCE_ROOT=/evidence   # read-only case images
export CASE_OUTPUT=/cases        # writable run output
```

See `examples/sample-evidence/README.md` for bundled demo evidence layout.

## Step 1 — evidence integrity

```bash
# Manifest (SHA-256 all files under a case directory)
cold-box-evidence manifest examples/sample-evidence

# Pre/post integrity check (e.g. before and after an investigation run)
cold-box-evidence integrity-begin examples/sample-evidence
cold-box-evidence integrity-check examples/sample-evidence
```

## Step 2 — audit log

Every tool call gets an append-only `audit.jsonl` entry with `audit_id`, timestamp,
tool name, args, result digest, and iteration. Lines are hash-chained for tamper detection.

```bash
# After a run writes /cases/<case-id>/audit.jsonl
cold-box-audit verify /cases/sample/audit.jsonl
cold-box-audit lookup /cases/sample/audit.jsonl <audit_id>
cold-box-audit summary /cases/sample/audit.jsonl
```

## Step 3 — MCP (first tool)

FastMCP server with audited tools. Every call writes to `CASE_OUTPUT/<case_id>/audit.jsonl`
and returns structured JSON including `audit_id`.

```bash
export EVIDENCE_ROOT=/evidence
export CASE_OUTPUT=/cases
export VOL3=/opt/postmortem/bin/vol   # optional

# stdio MCP server (Cursor / Claude Desktop)
cold-box-mcp

# Tool: mem_pslist(case_id, memory_relpath, iteration=0)
# Example memory path: ali-hadi-1/memdump/memdump.mem
```

## License

MIT (to be added before public release)
