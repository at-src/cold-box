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

## Step 4 — Wave 1 tool set (8 tools)

All tools append to `CASE_OUTPUT/<case_id>/audit.jsonl` and return `audit_id`.

| Tool | Input |
|------|--------|
| `mem_pslist` | Memory image under `EVIDENCE_ROOT` (`.mem`, `.raw`, `.dmp`, …) |
| `mem_psscan` | Same |
| `mem_cmdline` | Same |
| `disk_parse_prefetch` | `.pf` file path |
| `disk_parse_amcache` | `Amcache.hve` path |
| `disk_parse_evtx` | `.evtx` file path |
| `disk_parse_mft` | Extracted `$MFT` / `.mft` file |
| `evidence_manifest` | Case directory under `EVIDENCE_ROOT` |

Backend env vars (optional):

```bash
export VOL3=/opt/postmortem/bin/vol
export PREFETCH_PARSER=/opt/postmortem/tools/parse_prefetch.py
export EVTX_ECMD=EvtxECmd
export AMCACHE_PARSER=AmcacheParser
export MFTECMD=MFTECmd
```

## Step 5 — verifier (R1)

Deterministic contradiction checks on tool outputs — no LLM.

**R1 `hidden_process`:** process in psscan absent from pslist, or same PID with mismatched name (offsets may differ between Vol plugins).

```bash
# JSON files can be mem_pslist/mem_psscan tool responses (with optional audit_id wrapper)
cold-box-verify r1 \
  --pslist examples/sample-verifier/r1-pslist.json \
  --psscan examples/sample-verifier/r1-psscan.json

cold-box-verify run --pslist pslist.json --psscan psscan.json
```

Bundled synthetic demo where R1 fires: `examples/sample-verifier/r1-*.json`.

## License

MIT (to be added before public release)
