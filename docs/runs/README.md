# Run evidence

Each subfolder is one complete cold-box-room hallway run on a real forensic image. Only post-fix runs are committed here — all runs below were produced after the current codebase was stable.

| Run | Dataset | Track | Result | Date |
|-----|---------|-------|--------|------|
| [cfreds-leakage](cfreds-leakage/) | NIST CFReDS 2015 Data Leakage PC | Claude Code interactive | 100% | 2026-06-15 |

More runs added as they complete.

---

## What each run folder contains

```
<run-id>/
├── README.md               — summary, results table, reproduce command
├── audit.jsonl             — representative tool executions (sanitised paths)
├── hallway.json            — room promotion timeline + plan scores
├── layer1_analyst_log.md   — Room 2 extraction write-up (agent-authored, audit IDs linked)
└── layer2_analyst_log.md   — Room 3 analysis write-up (agent-authored, skill IDs linked)
```

Full logs (tool_log.jsonl, scratch/ per-run stdout) are on the evaluation VM at `records/<run-id>/` — not committed because they contain evidence-derived artifacts.

## How to add a new run

```bash
# After the run completes:
mkdir docs/runs/<run-id>
cp cold-box-room/records/<run-id>/layer1_analyst_log.md docs/runs/<run-id>/
cp cold-box-room/records/<run-id>/layer2_analyst_log.md docs/runs/<run-id>/
# Write README.md and sanitised audit.jsonl + hallway.json

git add docs/runs/<run-id>/
```
