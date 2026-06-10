# LLM head-to-head benchmark — cold-box vs Agentic-DART

> **Update 2026-06-10 (v2 — engine rework).** After this benchmark we reworked the
> autonomous loop and output layer. Re-run results (LLM, `claude-sonnet-4-6`), artifacts
> saved under `dont-commit-main-plan/llm-runs-v2/`:
>
> | Case | Old (v1) | New (v2) | Change |
> |------|----------|----------|--------|
> | Sample iterations | 18 | **12** | converges |
> | Ali iterations | 25 (hit cap) | **15** | converges (was looping) |
> | Ali final confidence | 0.35 | **0.75** | real conclusion |
> | Ali final hypothesis | `"Contradiction R7,R14,R15,R18,R19 — revising"` (placeholder) | full ATT&CK attack-chain narrative | fixed |
> | Ali required recall | 1.0 | **1.0** | held (no recall lost) |
> | Sample API cost | $0.50 | **$0.16** | 3.1× cheaper |
> | Ali API cost | $0.81 | **$0.155** | 5.2× cheaper |
>
> **Root causes fixed:** (1) the loop treated every fired verifier rule (`status=="contradiction"`)
> as "your hypothesis is wrong — keep revising" and overwrote the hypothesis with a placeholder
> every turn, so it could never converge; (2) findings were emitted as verifier *telemetry*
> ("22 web attack requests") rather than an analyst narrative; (3) the reasoner re-sent each rule's
> full `sources` array every turn, ballooning cache-read tokens. New: confirmed signals are treated
> as evidence to *incorporate*, a productive-stall early-stop + failed-call/evidence-gap guard,
> and a grounded synthesis layer (`postmortem_agent/synthesis.py`) that emits an ATT&CK
> kill-chain attack story, primary + alternative hypotheses, and remediation — every claim still
> tied to a SHA-256-audited `audit_id`. See `dont-commit-main-plan/llm-runs-v2/llm-ali/report.md`.



**Date:** 2026-06-10  
**Host:** `/opt/postmortem` (AWS EC2 lab box)  
**Model (both agents):** `claude-sonnet-4-6` via Anthropic API (`ANTHROPIC_API_KEY` in `/opt/postmortem/.env`)  
**Max iterations (both):** 25  
**Mode:** Live LLM brain on both sides (not deterministic/scripted)

This document is meant for **external audit** (e.g. paste into Opus with: “read this file and the linked artifacts, then assess which agent performed better and whether findings are supported by evidence”).

---

## Evidence under test

| Case | Description | Agentic-DART `DART_EVIDENCE_ROOT` | cold-box |
|------|-------------|-----------------------------------|----------|
| **Sample** | DART bundled lab pack (IP-KVM + web + persistence) | `/opt/ref/agentic-dart/examples/sample-evidence` | `EVIDENCE_ROOT=/opt/ref/agentic-dart/examples/sample-evidence` |
| **Ali** | Ali Hadi #1 widened extract (web overlay + memory) | `/home/ubuntu/cases/ali-hadi-1/extracted` | `EVIDENCE_ROOT=/evidence`, `--from-cache ~/cases/ali-hadi-1/cache`, `--extracted-root ~/cases/ali-hadi-1/extracted` |

**Ground truth (cold-box scorer):**

- Sample: [`/opt/postmortem/ground-truth/dart-sample-evidence.json`](/opt/postmortem/ground-truth/dart-sample-evidence.json)
- Ali: [`/opt/postmortem/ground-truth/ali-hadi-1.json`](/opt/postmortem/ground-truth/ali-hadi-1.json)

**Note on DART scoring:** DART live mode emits findings in a free-form `REPORT:` JSON block inside `live_transcript.txt`. There is no verifier gate or `audit.jsonl` chain linking each finding to a tool call. Theme recall for DART below is **keyword match** against the same ground-truth keywords (generous; audit separately).

---

## Executive summary

| Case | DART live required themes | cold-box LLM required themes | Faster agent | More tool calls | Auditable findings |
|------|---------------------------|------------------------------|--------------|-----------------|-------------------|
| **Sample** | 100% (3/3 + optional themes in report) | **100%** (3/3 required, 5/5 full) | DART (14 vs 18 iter) | DART (50 vs 18) | **cold-box** (verifier + audit chain) |
| **Ali** | 100% (5/5 keywords in report) | **100%** (5/5 required) | DART (11 vs 25 iter) | DART (36 vs 25) | **cold-box** (R7 malfind + audit chain) |

**Neither agent missed required lab themes** on this run. Difference is **architecture**:

- **DART:** Claude + 72 MCP tools → long narrative + `REPORT:` findings (12 sample / 10 Ali).
- **cold-box:** Claude + 52 MCP tools → **verifier R1–R20** emits findings only on contradictions; every finding has `audit_id`(s).

---

## Results — DART sample-evidence

| Metric | Agentic-DART live | cold-box `--llm` |
|--------|-------------------|------------------|
| Case output dir | `/tmp/llm-h2h/dart-sample` | `/tmp/bench-report/h2h-cb-sample` |
| Iterations | 14 | 18 |
| Tool calls | 50 (36 unique tools) | 18 (audited MCP) |
| Findings count | 12 in `REPORT:` JSON | 10 in `findings.json` |
| Self-correction | Yes (KVM vs logon in narrative) | Yes (verifier-driven) |
| cold-box required recall | — | **1.0** (F-001, F-002, F-003) |
| cold-box full recall | — | **1.0** (+ F-004 self-correction, F-WEB) |
| API usage | in 40,592 / out 8,972 / cache read 233,422 | ~18 API calls; prompt cache enabled |

**DART finding IDs in report (sample):** F-001 … F-012 (phishing, execution, persistence, scheduled task, IP-KVM, exfil, web, etc.)

**cold-box verifier rules fired (sample):** R5, R11, R12, R13, R14, R15, R16, R20 + hypothesis + narrative

---

## Results — Ali Hadi

| Metric | Agentic-DART live | cold-box `--llm` |
|--------|-------------------|------------------|
| Case output dir | `/tmp/llm-h2h/dart-ali` | `/tmp/bench-report/h2h-cb-ali` |
| Iterations | 11 | 25 (hit cap) |
| Tool calls | 36 (26 unique) | 25 (audited MCP) |
| Findings count | 10 in `REPORT:` JSON | 7 in `findings.json` |
| Memory / malfind | Transcript notes memory path blocked in env | **R7 malfind** → AH-5 |
| Timeline (AH-6) | Described in cross-source narrative | **R15** + hypothesis tag |
| cold-box required recall | — | **1.0** (AH-1, AH-3, AH-5, AH-6, AH-7) |
| API usage | in 69,504 / out 8,435 / cache read 259,647 | 25 API calls |

**DART Ali attack chain (from transcript):** sqlmap → LFI `/etc/passwd` → SSRF IMDS → webshell upload → RCE `shell.php?cmd=id`

**cold-box Ali rules fired:** R7, R14, R15, R18, R19 + hypothesis + narrative

---

## Raw artifacts — audit this first

> Paths under `/tmp/` were valid at run time on the lab box. Copy elsewhere if you need long-term retention.

### Agentic-DART — sample

| Artifact | Path | ~Size |
|----------|------|-------|
| **Full LLM transcript + REPORT JSON** | [`/tmp/llm-h2h/dart-sample/live_transcript.txt`](/tmp/llm-h2h/dart-sample/live_transcript.txt) | 14 KB, 128 lines |
| Tool call log (JSONL) | [`/tmp/llm-h2h/dart-sample/live_tool_calls.jsonl`](/tmp/llm-h2h/dart-sample/live_tool_calls.jsonl) | 9 KB, 50 lines |
| Run summary (tokens, iterations) | [`/tmp/llm-h2h/dart-sample/live_summary.json`](/tmp/llm-h2h/dart-sample/live_summary.json) | 0.3 KB |
| Console stderr log | [`/tmp/llm-h2h/dart-sample.log`](/tmp/llm-h2h/dart-sample.log) | 2 KB |

### Agentic-DART — Ali

| Artifact | Path | ~Size |
|----------|------|-------|
| **Full LLM transcript + REPORT JSON** | [`/tmp/llm-h2h/dart-ali/live_transcript.txt`](/tmp/llm-h2h/dart-ali/live_transcript.txt) | 13 KB, 131 lines |
| Tool call log (JSONL) | [`/tmp/llm-h2h/dart-ali/live_tool_calls.jsonl`](/tmp/llm-h2h/dart-ali/live_tool_calls.jsonl) | 7 KB, 36 lines |
| Run summary | [`/tmp/llm-h2h/dart-ali/live_summary.json`](/tmp/llm-h2h/dart-ali/live_summary.json) | 0.2 KB |
| Console stderr log | [`/tmp/llm-h2h/dart-ali.log`](/tmp/llm-h2h/dart-ali.log) | 2 KB |

### cold-box — sample

| Artifact | Path | ~Size |
|----------|------|-------|
| **Findings (verifier-backed)** | [`/tmp/bench-report/h2h-cb-sample/findings.json`](/tmp/bench-report/h2h-cb-sample/findings.json) | 11 KB |
| **Audit chain (SHA-256 linked)** | [`/tmp/bench-report/h2h-cb-sample/audit.jsonl`](/tmp/bench-report/h2h-cb-sample/audit.jsonl) | 11 KB, 18 entries |
| Investigation progress | [`/tmp/bench-report/h2h-cb-sample/progress.jsonl`](/tmp/bench-report/h2h-cb-sample/progress.jsonl) | 34 KB |
| Human report | [`/tmp/bench-report/h2h-cb-sample/report.md`](/tmp/bench-report/h2h-cb-sample/report.md) | 15 KB |
| Narrative | [`/tmp/bench-report/h2h-cb-sample/narrative.md`](/tmp/bench-report/h2h-cb-sample/narrative.md) | 4 KB |
| Structured report | [`/tmp/bench-report/h2h-cb-sample/report.json`](/tmp/bench-report/h2h-cb-sample/report.json) | — |
| Console log | [`/tmp/llm-h2h/cb-sample.log`](/tmp/llm-h2h/cb-sample.log) | 4 KB |

### cold-box — Ali

| Artifact | Path | ~Size |
|----------|------|-------|
| **Findings** | [`/tmp/bench-report/h2h-cb-ali/findings.json`](/tmp/bench-report/h2h-cb-ali/findings.json) | 4 KB |
| **Audit chain** | [`/tmp/bench-report/h2h-cb-ali/audit.jsonl`](/tmp/bench-report/h2h-cb-ali/audit.jsonl) | 14 KB, 25 entries |
| Progress | [`/tmp/bench-report/h2h-cb-ali/progress.jsonl`](/tmp/bench-report/h2h-cb-ali/progress.jsonl) | 41 KB |
| Report | [`/tmp/bench-report/h2h-cb-ali/report.md`](/tmp/bench-report/h2h-cb-ali/report.md) | 8 KB |
| Narrative | [`/tmp/bench-report/h2h-cb-ali/narrative.md`](/tmp/bench-report/h2h-cb-ali/narrative.md) | 1 KB |
| Structured report | [`/tmp/bench-report/h2h-cb-ali/report.json`](/tmp/bench-report/h2h-cb-ali/report.json) | — |
| Console log | [`/tmp/llm-h2h/cb-ali.log`](/tmp/llm-h2h/cb-ali.log) | 1 KB |

---

## cold-box score reports (machine-readable)

Reproduce:

```bash
cd /opt/postmortem
cold-box-agent score --output-dir /tmp/bench-report/h2h-cb-sample \
  --ground-truth ground-truth/dart-sample-evidence.json --self-corrected

cold-box-agent score --output-dir /tmp/bench-report/h2h-cb-ali \
  --ground-truth ground-truth/ali-hadi-1.json --self-corrected
```

**Sample score (2026-06-10):** `required_recall=1.0`, `recall=1.0`, `finding_count=10`, `missed=[]`

**Ali score (2026-06-10):** `required_recall=1.0`, `recall=0.857`, `finding_count=7`, `missed=[]`

---

## How to reproduce

### Prerequisites

```bash
cd /opt/postmortem
source bin/load-agent-env   # loads ANTHROPIC_API_KEY from .env — never commit .env
pip install anthropic mcp    # DART live deps
```

### Agentic-DART live — sample

```bash
export PYTHONPATH="/opt/ref/agentic-dart/dart_mcp/src:/opt/ref/agentic-dart/dart_audit/src:/opt/ref/agentic-dart/dart_agent/src:/opt/ref/agentic-dart/dart_corr/src"
export DART_EVIDENCE_ROOT=/opt/ref/agentic-dart/examples/sample-evidence
export DART_MODEL=claude-sonnet-4-6

cd /opt/ref/agentic-dart
python3 -m dart_agent --mode live \
  --case h2h-dart-sample \
  --out /tmp/llm-h2h/dart-sample \
  --model claude-sonnet-4-6 \
  --max-iterations 25 \
  --prompt "Investigate this dead Windows host for compromise. Use forensic MCP tools. End with REPORT: JSON."
```

### Agentic-DART live — Ali

```bash
bash /opt/postmortem/scripts/h2h_dart_ali.sh
```

### cold-box LLM — sample

```bash
cd /opt/postmortem
source bin/load-agent-env
EVIDENCE_ROOT=/opt/ref/agentic-dart/examples/sample-evidence \
  cold-box-agent run --case-id h2h-cb-sample --evidence-case . \
  --llm --max-iterations 25
```

### cold-box LLM — Ali

```bash
bash /opt/postmortem/scripts/h2h_cb_ali.sh
```

---

## Architecture comparison (for auditors)

| | Agentic-DART live | cold-box LLM |
|--|-------------------|--------------|
| MCP tools | 72 | 52 |
| Finding source | LLM `REPORT:` block | Verifier rules R1–R20 (`contradiction` only) |
| Audit | `live_tool_calls.jsonl` (tool inputs/outputs) | `audit.jsonl` hash chain + `audit_id` on every finding |
| Hallucination control | Prompt + “cite tool calls” in REPORT | Mechanical: no verifier pass → no confirmed finding |
| Prompt caching | System + last tool definition | System + tool catalog + automatic multi-turn cache |
| Playbook | Embedded in DART system prompt | Policy/verifier loop + optional LLM reasoner |

---

## Suggested questions for Opus / human audit

1. For each DART `REPORT` finding, does `live_tool_calls.jsonl` contain supporting tool output?
2. For each cold-box finding, does `audit.jsonl` entry match the claim in `findings.json`?
3. Are any DART findings **stronger** than cold-box (extra context cold-box verifier missed)?
4. Are any cold-box findings **safer** (mechanically provable) than DART narrative?
5. On Ali, DART noted memory analysis blocked — is that env config or tool gap?
6. cold-box Ali hit iteration cap still in “contradiction revising” — should the loop stop earlier when required themes are satisfied?

---

## Related repo docs

- Implementation plan: [`/opt/postmortem/dont-commit-main-plan/IMPLEMENTATION-PLAN.md`](/opt/postmortem/dont-commit-main-plan/IMPLEMENTATION-PLAN.md)
- Prompt caching notes: [`/opt/postmortem/dont-commit-main-plan/claudecahce.md`](/opt/postmortem/dont-commit-main-plan/claudecahce.md)
- Env template: [`/opt/postmortem/.env.example`](/opt/postmortem/.env.example)

---

## One-line pitch (sample case)

> On DART `sample-evidence`, both agents with Claude Sonnet 4.6 achieved **100% required theme recall**; DART ran **50 tool calls in 14 iterations** with **12 narrative findings**; cold-box ran **18 audited tools in 18 iterations** with **verifier-gated findings** and a **verified SHA-256 audit chain**.
