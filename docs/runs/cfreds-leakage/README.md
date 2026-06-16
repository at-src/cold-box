# Run: cfreds-leakage

**Dataset:** NIST CFReDS 2015 Data Leakage PC (4-segment E01, 21GB)  
**Track:** Claude Code interactive (`cold-box-room-hallway-cc`)  
**Model:** claude-sonnet-4-6  
**Date:** 2026-06-15  
**Hallway:** complete (Room 1 → A → 2 → B → 3)

---

## Results

| Metric | Result |
|--------|--------|
| Required checks | **100%** (4/4) |
| Optional checks | **100%** (1/1 in-scope; timezone N/A — rm# image not staged) |
| Layer 1 plan score | **100%** (12/12 steps passed) |
| Layer 2 plan score | **100%** (10/10 steps passed) |
| Successful extractions | **32** |
| Self-score L1 / L2 | **9 / 9** |
| Wall time | ~27 min |
| Self-correction events | **1** (fcat path failure → ifind → icat) |

---

## Key finding

**Primary forensic conclusion:** Insider data leakage via USB removable media by user `admin11`. Anti-forensic cleanup performed: 4 files batch-deleted via Recycle Bin at exactly `2015-03-24 19:51:47 UTC` — simultaneous timestamp is evidence of scripted deletion, not manual removal. Chrome history (4 URLs, no cloud storage) definitively rules out web-based exfiltration.

---

## Files in this folder

| File | Contents |
|------|----------|
| [`audit.jsonl`](audit.jsonl) | 7 representative tool executions including self-correction sequence |
| [`hallway.json`](hallway.json) | Room promotion timeline and plan checkpoint scores |
| [`layer1_analyst_log.md`](layer1_analyst_log.md) | Layer 1 extraction findings (full agent write-up) |
| [`layer2_analyst_log.md`](layer2_analyst_log.md) | Layer 2 analysis findings (full agent write-up) |

---

## Self-correction trace

```
CB-541b86fa41d7  fcat  exit=1  "fcat: error opening image file"
       ↓ agent pivoted — no human intervention
CB-70493459ba6a  ifind exit=0  "58912"    ← inode for SYSTEM hive
CB-62ec250cd23c  icat  exit=0  [12.4MB regf binary]
```

Full audit trail: `cold-box-room/records/cfreds-leakage/audit.jsonl` on the evaluation VM.

---

## Reproduce

```bash
cd /opt/postmortem/cold-box-room
source ../.venv/bin/activate
pip install -e ".[dev,mcp]"

cold-box-room intake \
  --case-id cfreds-leakage \
  --source /evidence/nist-ndlc/images/cfreds_2015_data_leakage_pc.E01 \
  --link

cold-box-room r1-check --case-id cfreds-leakage --promote

# Then open Claude Code in cold-box-room/ — MCP loads from .mcp.json
# Follow CLAUDE.md workflow: get_hallway_status → rooms A → 2 → B → 3
```
