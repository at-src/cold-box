# Dead-host Windows investigation

This is the top-level playbook for cold-box on a powered-off or imaged Windows host. The agent follows a fixed phase order today; an LLM will use the same tools and verifier later.

## Phase flow

1. **Triage** — manifest the case, note what artifacts exist (memory image? prefetch? MFT?).
2. **Hypothesis** — state what you think happened and a confidence score.
3. **Validate** — run MCP tools, append `audit.jsonl`, store raw JSON keyed by tool name.
4. **Verifier** — run deterministic rules R1–R6 on the collected tool output.
5. **Self-correction** — if a rule returns `contradiction`, run follow-up tools, lower confidence, add a progress note containing the words `self-correction`.
6. **Finalize** — write `findings.json`, `report.md`, `report.json`. Confirmed claims must include audit IDs.

Partial closeout is allowed at `--max-iterations`, but unresolved contradictions stay in the report.

## Verifier cheat sheet

| Rule | Question it asks |
|------|------------------|
| R1 | Does psscan show a PID/name that pslist cannot explain? |
| R2 | Does memory show an exe with no prefetch or amcache trail? |
| R4 | Does MFT show $SI created before $FN on the same entry? |
| R5 | Does prefetch name a binary that is not on disk in this case? |
| R6 | Does netscan show a connection owned by a PID missing from pslist? |

R3 (`phantom_logon`) is not implemented yet.

Contradiction does not mean “stop.” It means gather more evidence with a targeted tool or mark the item unresolved with sources attached.

## Environment

```bash
export EVIDENCE_ROOT=/path/to/case          # read-only
export CASE_OUTPUT=/path/to/output          # audits, reports, scratch
source .venv/bin/activate
```

Lab default: `EVIDENCE_ROOT=examples/sample-evidence`  
Production: `EVIDENCE_ROOT=/evidence` plus `--memory` for RAM images.

## Commands that actually run today

Synthetic R1 demo (~1 second):

```bash
bash examples/demo-run.sh
```

Disk + verifier + accuracy check on our lab case:

```bash
bash examples/demo-case-run.sh
```

Agent only (fixtures, no Vol):

```bash
cold-box-agent run \
  --case-id my-run \
  --evidence-case synthetic-r1 \
  --synthetic \
  --fixture-dir examples/sample-verifier
```

Verifier by hand:

```bash
cold-box-verify run \
  --pslist examples/sample-verifier/r1-pslist.json \
  --psscan examples/sample-verifier/r1-psscan.json \
  --prefetch examples/sample-verifier/r5-prefetch.json \
  --mft examples/sample-verifier/r4-mft.json \
  --netscan examples/sample-verifier/r6-netscan.json \
  --evidence-root examples/sample-evidence
```

Measure rule recall on fixtures:

```bash
python scripts/measure_accuracy.py
```

## Demo story (video beat)

1. Agent assumes normal service-host activity (low–medium confidence).
2. R1 fires: hidden process in psscan.
3. Agent runs `mem_cmdline`, bumps confidence, logs self-correction in `progress.jsonl`.
4. Show matching lines in `audit.jsonl` (tool name → audit_id).
5. Prove guardrails: calling `execute_shell` through MCP dispatch raises `ToolNotFound` (`tests/test_mcp_bypass.py`).

## Where to go deeper

- Process and network detail → `skills/memory-forensics/SKILL.md`
- Prefetch, MFT, timestomp → `skills/windows-artifacts/SKILL.md`
