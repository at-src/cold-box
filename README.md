# Cold-box-room — Autonomous DFIR Agent on the SIFT Hallway

> *The evidence is sealed. The plan is written. Every tool run is on the record. The agent investigates — the harness enforces discipline.*

**Submission:** [SANS FIND EVIL! Hackathon 2026](https://findevil.devpost.com/)  
**Repository:** [github.com/at-src/cold-box](https://github.com/at-src/cold-box)  
**License:** [MIT](./LICENSE)  
**Architecture:** Custom MCP Server + Claude Code as the agentic framework  

---

## Results

Autonomous full-hallway runs on real forensic images, zero human intervention, `claude-sonnet-4-6`:

| Case | Benchmark | Accuracy | Wall time | Agent turns |
|------|-----------|----------|-----------|-------------|
| Terry work USB holdout | `terry_usb` | **100%** (4/4 req · 2/2 opt) | ~16 min | 89 |
| NIST CFReDS Data Leakage PC | `ndlc_leakage_pc` | **100%** (4/4 req · 1/1 opt) | ~27 min | — |
| Unit + integration suite | harness + guards + executor | **183/183 tests pass** | seconds | — |

Every finding in both reports traces back to a specific `audit_id` row in `audit.jsonl`. Reproduce any score with `scripts/score_e2e_accuracy.py`.

---

## Table of contents

- [The design philosophy](#the-design-philosophy)
- [How the hallway works](#how-the-hallway-works)
- [Architecture and trust boundaries](#architecture-and-trust-boundaries)
- [Self-correction](#self-correction)
- [Quick start — judges](#quick-start--judges)
- [Submission components 1–8](#submission-components-18)
- [What comes next](#what-comes-next)

---

## The design philosophy

Most agentic DFIR prototypes fail in one of two ways.

The first way: **too much freedom.** A raw LLM with `execute_shell_cmd` will run any command, hallucinate findings it can't verify, modify evidence by accident, and produce reports with no traceable chain. When Protocol SIFT's baseline agent gets it wrong, there is no audit trail to understand why.

The second way: **too little freedom.** Rule engines and playbook YAML solve hallucination by hardcoding analyst knowledge as decision trees. When path-based extraction fails, the rule fires the inode fallback. When the playbook encounters a case class it hasn't seen before, it fails — not because the AI can't reason about it, but because the YAML never covered it. The analyst is in a box of pre-written rules, not investigating.

**Cold-box-room takes a different position:** a senior analyst doesn't need a flowchart. They need sealed evidence, a structured methodology, and an audit trail. Give them those three things and let them investigate.

The rooms are chain-of-custody protocol, not an if-else tree.

- They enforce **when** the agent can act: no extraction before a written plan, no analysis before extraction is scored.
- They enforce **how** the agent proves its work: no step passes without an `audit_id`, no writeup submits with unresolved holds.
- They leave **what** to investigate entirely to Claude — which SIFT tools to run, what the evidence means, which hypotheses to form, how to self-correct when a path fails.

The result is an agent that behaves like a disciplined senior analyst — not because we enumerated every decision it should make, but because the environment it operates in demands rigor at every step.

---

## How the hallway works

```
Room 1 (seal) → Room A (plan) → Room 2 (extract) → Room B (plan) → Room 3 (analyse) → complete
```

Each room exposes a different set of MCP tools. The harness enforces the boundary in code — calling the wrong tool in the wrong room raises an error before execution. Promotion to the next room requires passing a harness checkpoint, not just a model promise.

### Room 1 — the evidence table

Evidence is staged once and sealed. The original file gets read-only permissions and a manifest. No agent ever operates in Room 1 after sealing. The door locks permanently — `return_to_room` rejects `"1"` in code, not in a prompt.

What this buys: even if Claude is compromised, jailbroken, or just wrong, it cannot touch the original evidence. Room 2 operates on a copy.

### Room A — extraction planning

The agent arrives with the sandbox copy visible (`list_sandbox_files`) and the full SIFT tool catalog browsable (`list_sift_tools`, `describe_sift_tool`). It cannot run tools yet. It writes `plan_a.md` — a numbered list of what to extract and why — which the harness formalizes into `plan_a.py` with typed checkpoints. Once `plan_a.py` exists and passes validation, Room 2 opens.

This separation matters. An agent forced to write a plan before extracting actually thinks about what it's looking for. One handed a shell prompt immediately starts running commands.

### Room 2 — SIFT extraction

The agent runs its plan step by step using `run_sift_tool(tool_id="SIFT-###")`. Catalog: 234 tools covering image metadata, partition geometry, filesystem enumeration, registry extraction, event logs, browser artifacts, USN journal, prefetch, shellbags, recycle bin — the full SIFT toolkit.

Every `run_sift_tool` call returns an `audit_id`. Each plan step must cite one before it can pass. The harness writes the tool log; the agent writes findings. They cannot be confused.

At the end of Room 2 the agent submits a Layer 1 writeup — findings, reasoning, and a self-score. If self-score < 9 or plan score < 70% or any step is unresolved, the harness blocks the submit. The agent must fix and retry.

Step statuses: `passed` (evidence found, `audit_id` attached) · `fail` (ran the tool, evidence not there) · `not_relevant` (dropped from scoring pool) · `held_for_later` (blocks submit until resolved).

When Room 2 passes, `submit_layer1_writeup` automatically promotes to Room B.

### Room B — analysis planning

Same structure as Room A, but now the agent reads what was actually extracted (`read_layer1_tool_log`, `read_layer1_analyst_log`) and plans what to analyse. It can also browse the 171 runnable skills (`list_skills`, `describe_skill`). Writes `plan_b.md` → harness formalizes → `plan_b.py` → Room 3 opens.

### Room 3 — skill analysis

The agent runs skills via `run_skill(skill_id="SKILL-###")` — pre-built analysis playbooks for USB device correlation, shellbag analysis, SAM/hive parsing, event log session timelines, recycle bin $I metadata, jump list artifact reconstruction, prefetch execution history, MFT+USN timeline consolidation, and more.

If analysis reveals a gap in extraction — a missing artifact, an unexplored artifact class — the agent calls `return_to_room(2)`, runs the missing SIFT tool, and returns to Room 3. Room A and Room B stay open through the full hallway. Any revisit forces the agent to document corrections in the Layer 2 writeup; the harness blocks submission if corrections are empty after a revisit.

Once all plan steps are resolved, score ≥ 70%, and self-score ≥ 9, `submit_layer2_writeup` produces the final DFIR report and marks the case complete.

---

## Architecture and trust boundaries

**Pattern:** Custom MCP Server + Claude Code as the execution engine.

The MCP server exposes structured tool functions — not `execute_shell_cmd`. Claude cannot run arbitrary commands because arbitrary commands do not exist on the wire. This is the distinction the hackathon describes as "the most sound architecture in the evaluation."

### Full system diagram

```mermaid
flowchart TB
  subgraph evidence["Evidence (read-only)"]
    E01["disk image / E01 / directory"]
  end

  subgraph room1["Room 1 — SEALED FOREVER"]
    INT["intake + EWF auto-chain"]
    SEAL["manifest + chmod read-only"]
    LOCK["return_to_room('1') → error"]
  end

  subgraph rooma["Room A — plan only"]
    LSF["list_sandbox_files"]
    LST["list_sift_tools / describe"]
    WPA["write_plan_a_md"]
    FPA["formalize_plan_a → plan_a.py"]
  end

  subgraph room2["Room 2 — SIFT extraction"]
    SBX["R2 sandbox copy"]
    RST["run_sift_tool (SIFT-001…234)"]
    AUD["audit.jsonl ← every run"]
    SL1["submit_layer1_writeup"]
  end

  subgraph roomb["Room B — plan only"]
    RL1["read_layer1_tool_log / analyst_log"]
    WPB["write_plan_b_md"]
    FPB["formalize_plan_b → plan_b.py"]
  end

  subgraph room3["Room 3 — skill analysis"]
    RSK["run_skill (SKILL-001…171)"]
    SL2["submit_layer2_writeup + corrections"]
    RTR["return_to_room (A / 2 / B)"]
  end

  subgraph out["Output"]
    REP["DFIR report"]
    ACC["accuracy score"]
    TRAIL["full audit trail"]
  end

  E01 --> INT --> SEAL --> LSF
  SEAL --> SBX
  LSF --> WPA --> FPA --> RST
  RST --> AUD --> SL1 --> RL1
  RL1 --> WPB --> FPB --> RSK
  RSK --> SL2 --> REP --> ACC
  RSK -.->|gap found| RTR -.->|return| RSK
  AUD --> TRAIL
```

### Architectural guardrails — enforced in code

| Boundary | What it prevents | Where |
|----------|-----------------|-------|
| Room gate (`require_room`) | Wrong-room tools raise before execution | `r1/hallway.py` |
| Per-room allowlist | `run_sift_tool` blocked in Room A/B | `planning/guard.py` |
| R1 seal | Write to staged evidence → `TouchForbiddenError` | `r1/seal.py` |
| Room 1 lock | `return_to_room("1")` → error | `r1/hallway.py` |
| Catalog-only execution | No free shell; only `SIFT-###` / `SKILL-###` IDs | `r2/executor.py` |
| Sandbox input scope | Tool inputs must be under `sandbox/{case_id}/` | `r2/sandbox_input.py` |
| Scratch-only output | Path rewrite blocks writes outside scratch | `r2/security.py` |
| Harness logbooks | Agent cannot append to tool/skill logs | `r2/tool_log.py` |
| Plan proof gate | `passed` requires `audit_id` or `run_id` | `planning/plan_py.py` |
| Submit gate | Held steps, low score, or missing self-score block submit | `planning/scoring.py` |

### Prompt-based guardrails — quality layer on top

System prompts and MCP instructions reinforce: cite `audit_id` in findings, plan before extracting, document corrections after any revisit. These sharpen analytical quality. The architectural walls above already prevent the failure modes that matter — wrong-room execution, evidence tampering, untraceable findings. The prompts are not the safety system; the code is.

If you bypass all the prompts and the model ignores every instruction, it still cannot: touch the original evidence, run a destructive command, skip writing a plan and jump straight to extraction, or pass a plan step without proof. Those are hard errors.

---

## Self-correction

Cold-box-room supports two forms of self-correction, both on the record.

**In-turn correction (most common):** When a tool call fails — path not found, wrong inode, unexpected output format — the agent pivots immediately. In the CFReDS run, path-based extraction failed for registry hives; the agent switched to `ifind` → inode lookup → `icat` by inode without any instruction to do so. This is real-time reasoning about failure, not a fallback rule.

**Cross-room correction:** When Room 3 analysis reveals a gap in the Layer 1 extractions — a missing artifact class, an unexplored timeline window — the agent calls `return_to_room(2)`, runs the missing SIFT tool, and returns to Room 3. The harness then requires a `corrections` field in the Layer 2 writeup documenting what was wrong, what was fixed, and why. This is enforced: submitting with a revisit and no corrections raises a checkpoint error.

Both forms produce an auditable record. Judges can trace exactly when the agent changed course, what triggered it, and what the outcome was.

---

## Quick start — judges

**Harness proof (no API key, 2 min):**

```bash
git clone https://github.com/at-src/cold-box.git
cd cold-box/cold-box-room
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q
# 183 tests, no spend
```

**Full autonomous run (API key + SIFT VM + evidence):**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export COLD_BOX_R1_STAT_ONLY=1      # skip MD5 on large E01s

# Claude Code track (recommended — Claude is the agent)
pip install -e ".[dev,mcp]"
cold-box-room-hallway-cc \
  --case-id terry-demo \
  --evidence /evidence/unseen-terry-usb/terry-work-usb-2009-12-11.E01

# Native Python track (same harness, Python agent loop)
cold-box-room-hallway \
  --run-id terry-demo \
  --evidence /evidence/unseen-terry-usb/terry-work-usb-2009-12-11.E01 \
  --benchmark terry_usb
```

Pass a **directory**, a single **E01**, or an **EWF chain** — E02–E04 segments auto-attach from the same folder.

**Environment variables:**

| Variable | Purpose | Default |
|----------|---------|---------|
| `COLD_BOX_R1_STAGING` | Sealed evidence root | `./r1-staging` |
| `COLD_BOX_R2_SANDBOX` | Working copy for tools | `./r2-sandbox` |
| `COLD_BOX_ROOM_RECORDS` | Plans, logs, audit trail | `./records` |
| `COLD_BOX_R1_STAT_ONLY` | Skip full hash on large images | unset |
| `ANTHROPIC_PROMPT_CACHE` | Enable prompt caching | unset |

---

## Submission components 1–8

### 1 — Code repository

| Item | Detail |
|------|--------|
| URL | https://github.com/at-src/cold-box |
| License | MIT — [`LICENSE`](./LICENSE) |
| Install | `pip install -e ".[dev,mcp]"` from `cold-box-room/` |
| Entry points | `cold-box-room-hallway-cc` · `cold-box-room-hallway` · `cold-box-room-mcp` |
| Tests | `pytest tests/` — 183 cases covering hallway flow, R1 seal, executor security, plan locking, evidence intake, accuracy scoring |

### 2 — Demo video

≤ 5 minutes · live terminal · audio narration · real forensic image · self-correction visible.

**Script:**
1. `cold-box-room-hallway-cc --case-id demo --evidence /evidence/...E01` — intake streams to terminal
2. Room A: agent calls `list_sandbox_files`, browses catalog, writes plan
3. Room 2: SIFT tool runs — highlight `audit_id` returned on `ewfinfo`, `mmls`, `fls`
4. Self-correction: agent detects path-based extraction failure, pivots to inode lookup, continues without human intervention
5. Room 3 skills → Layer 2 report → accuracy score printed

**Video URL:** *(add after recording)*

### 3 — Architecture diagram

Full diagram in [§ Architecture and trust boundaries](#architecture-and-trust-boundaries) above and [`docs/architecture.md`](docs/architecture.md).

Key distinction documented: prompt-based guardrails (quality layer) vs. architectural guardrails (hard errors). The architecture diagram identifies both.

### 4 — Written project description

**What it does**

Cold-box-room is an autonomous DFIR agent for the SANS SIFT Workstation. It runs a five-room hallway pipeline — seal evidence, plan extraction, run 234 SIFT tools, plan analysis, run 171 skills — producing Layer 1 and Layer 2 reports with every finding traceable to a specific tool execution via `audit_id`.

**How we built it**

Finite-state hallway with harness-gated room promotion. Per-room tool allowlists enforce phase separation in code. Catalog-driven SIFT executor: sandbox input, scratch output, sanitized CLI, blocked destructive binaries. Skill runtime routes nested tool calls through the same audit chain. Atomic file-locked plan updates for parallel step marking. Keyword benchmarks with manifest scope validation for reproducible accuracy scoring.

**The architectural decision**

We built a harness that enforces *when* the agent acts and *how* it proves its work — not *what* it investigates. Claude Code decides which artifacts to examine, which hypotheses to form, and how to recover from failures. The rooms enforce evidence handling protocol the same way a physical forensic lab does: the investigator is skilled and trusted; the chain of custody is not optional.

This is the opposite of encoding analyst knowledge as decision rules. Rules work until the edge case. A skilled agent in a disciplined harness generalises.

**Challenges**

EWF chain auto-attach (E01 → E02–E04 from a single path); file-locked concurrent plan updates during parallel SIFT dispatch; prompt caching + stat-only hashing to keep full runs under 30 minutes on 20+ GB images; accuracy scoring that validates against staged manifest so scores reflect exactly what evidence was provided.

**What we learned**

Phase separation is a stronger prompt than any instruction. When `run_sift_tool` literally does not exist in Room A, the agent plans first — not because it was told to, but because there is nothing else to do. Architectural walls produce better analytical behaviour than longer system prompts.

Full narrative: [`docs/PROJECT_STORY.md`](docs/PROJECT_STORY.md)

### 5 — Dataset documentation

Both datasets are public forensic corpora from NIST and SANS:

| Dataset | Source | What the agent found |
|---------|--------|---------------------|
| Terry work USB (2009-12-11.E01) | SANS holdout — not used in development | EWF/FAT32, volume label TERRYS WORK, **Advanced Keylogger / R54402.EXE**, partition offset 63, image MD5 verified |
| NIST CFReDS 2015 Data Leakage PC | [NIST CFReDS](https://cfreds.nist.gov/) | INFORMANT-PC / Windows 7 / NTFS, admin11 connected USB, batch deletion of 4 files + executable at identical timestamps 2015-03-24T19:51:47Z (anti-forensic cleanup), internet exfiltration ruled out via Chrome history (4 URLs only), full evidence chain: USBSTOR → shellbags → jump lists → PnP events → Security.evtx → Recycle Bin $I metadata → MFT/USN timeline |

Evidence images download separately and are not included in the repository. Paths on the evaluation VM: `/evidence/unseen-terry-usb/` and `/evidence/nist-ndlc/images/`.

Full details: [`docs/DATASETS.md`](docs/DATASETS.md)

### 6 — Accuracy report

**Scoring methodology:** keyword recall benchmarks against Layer 1/2 analyst logs, plans, and audit stdout. Required vs. optional keyword pools per case. Staging scope validated against `manifest.json` so scores reflect only what was actually provided.

```bash
cd cold-box-room
python scripts/score_e2e_accuracy.py --case-id CASE_ID --benchmark BENCHMARK_ID
```

**Terry USB holdout**

| Metric | Result |
|--------|--------|
| Required recall | **100%** (4/4) |
| Optional recall | **100%** (2/2) |
| Precision | **100%** |
| F1 | **1.0** |
| Wall time | 16 min |
| Layer 1 / 2 self-score | 9 / 9 |

**NIST CFReDS Data Leakage PC**

| Metric | Result |
|--------|--------|
| Required recall | **100%** (4/4) |
| Optional recall | **100%** (1/1 staged) |
| Precision on matched checks | **100%** |
| F1 | **1.0** |
| Wall time | 27 min |
| Layer 1 / 2 self-score | 9 / 9 |

**Known limitations:** analyst narrative logs summarise rather than enumerate every extracted artifact — complete artifact detail is in `layer1_tool_log` and `audit.jsonl`. No false positives observed on these benchmarks. Hallucination risk exists on artifact classes with no tool output (agent annotated such inferences as `[inferred]` in writeups).

**Evidence integrity:** R1 originals sealed at intake; all tool inputs from sandbox copy; manifest scope validated; no agent path to R1 after sealing. Tested: `tests/test_r1_table.py` (write block), `tests/test_evidence_intake.py` (directory + EWF intake).

Full report: [`docs/ACCURACY.md`](docs/ACCURACY.md)

### 7 — Try-it-out instructions

**Prerequisites:** Ubuntu 22.04+ or SIFT Workstation · Python 3.10+ · SIFT tools on `$PATH` · `ANTHROPIC_API_KEY` · evidence downloaded locally.

```bash
# 1. Clone and install
git clone https://github.com/at-src/cold-box.git
cd cold-box/cold-box-room
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp]"

# 2. Set environment
export ANTHROPIC_API_KEY=sk-ant-...
export COLD_BOX_R1_STAT_ONLY=1
```

**Three ways to run — pick one:**

**A) Claude Code interactive (recommended for judges exploring the system)**

Open Claude Code in the repo directory. The `.mcp.json` is already wired — Claude picks up all the MCP tools automatically. Then just describe what you want:

```bash
cd cold-box/cold-box-room
claude   # opens Claude Code interactive session
# Claude loads .mcp.json and has all cold-box-room MCP tools available.
# Prompt: "Run the hallway for case cfreds-demo with evidence at /path/to/image.E01"
```

**B) Claude Code headless — fully autonomous, streams to terminal**

```bash
cold-box-room-hallway-cc \
  --case-id terry-demo \
  --evidence /path/to/terry-work-usb-2009-12-11.E01
```

Intake runs in Python, then `claude --print` takes over. The full hallway streams live.

**C) Native Python agent — same harness, Python agent loop**

```bash
cold-box-room-hallway \
  --run-id terry-demo \
  --evidence /path/to/terry-work-usb-2009-12-11.E01 \
  --benchmark terry_usb
```

**Using with Cline, Cursor, or other agentic IDEs:**

The MCP server is a stdio server defined in `.mcp.json`. Any IDE that supports MCP servers can connect to it:

```json
{
  "mcpServers": {
    "cold-box-room": {
      "command": "cold-box-room-mcp",
      "args": []
    }
  }
}
```

Add this to your IDE's MCP config. The agent then has all cold-box-room tools available. Note: IDE-based agents rely on prompt adherence for workflow discipline; the harness still enforces evidence integrity and room gates architecturally regardless of which IDE drives it.

**After a run — generate the case bundle:**

```bash
# Assembles all artifacts into a single linked report directory
python scripts/bundle_case.py --case-id terry-demo

# Output: records/terry-demo/bundle/
#   REPORT.md            — final report, every audit_id is a hyperlink to raw stdout
#   EVIDENCE_INDEX.md    — index of all tool runs with links
#   audit/               — per-run stdout for every tool execution
#   plan_a.py / plan_b.py, all logs, hallway.json, manifest.json
```

```bash
# Verify tests (no API spend)
pytest tests/ -q

# Score a run against a benchmark
python scripts/score_e2e_accuracy.py --case-id terry-demo --benchmark terry_usb
```

**Environment variables:**

| Variable | Purpose | Default |
|----------|---------|---------|
| `COLD_BOX_R1_STAGING` | Sealed evidence root | `./r1-staging` |
| `COLD_BOX_R2_SANDBOX` | Working copy for tools | `./r2-sandbox` |
| `COLD_BOX_ROOM_RECORDS` | Plans, logs, audit trail | `./records` |
| `COLD_BOX_R1_STAT_ONLY` | Skip full hash on large images | unset |
| `ANTHROPIC_PROMPT_CACHE` | Enable prompt caching | unset |

### 8 — Agent execution logs

**Generate the bundle first** (assembles everything into one linked directory):

```bash
python scripts/bundle_case.py --case-id YOUR_CASE_ID
# → records/YOUR_CASE_ID/bundle/
```

Per-case records under `records/{case_id}/`:

| File | Contents |
|------|----------|
| `bundle/REPORT.md` | Final DFIR report — every `CB-xxxxxxxx` audit ID is a hyperlink to the raw stdout that produced the finding |
| `bundle/EVIDENCE_INDEX.md` | Index of every tool execution with direct links |
| `audit.jsonl` | One JSON object per tool run — `audit_id`, command, input SHA-256, stdout preview, timestamp |
| `hallway.json` | Room promotions, checkpoint results, revisit history |
| `plan_a.py` / `plan_b.py` | Live plan checkpoints — status, proof, timestamps |
| `layer1_tool_log.md` | Harness-owned tool execution log (agent cannot append) |
| `layer1_analyst_log.md` | Agent-written Layer 1 findings and self-score |
| `layer2_skill_log.md` | Skill run log with nested audit IDs |
| `layer2_analyst_log.md` | Final DFIR report with corrections |
| `scratch/CB-xxx_tool/stdout.txt` | Raw stdout for every tool execution |

**How to trace any finding (manual):**
1. Open `layer2_analyst_log.md` — pick a factual claim (e.g. "batch deletion at 2015-03-24T19:51:47Z")
2. Find the `audit_id` cited next to it (e.g. `CB-30bc6f63a2bd`)
3. `grep CB-30bc6f63a2bd audit.jsonl` — exact command, input file, stdout preview
4. Full stdout at `scratch/CB-30bc6f63a2bd_*/stdout.txt`

**How to trace any finding (bundle):**
Open `bundle/REPORT.md` in any markdown viewer. Every audit ID is already a hyperlink.

Sample excerpts: [`docs/submission-logs/`](docs/submission-logs/)

---

## What comes next

Cold-box-room v1 investigates a box you already know is compromised. The architecture is designed to grow.

**Near term**
- SHA-256-chained audit (each row signs the previous — tamper-evident trail)
- Multi-artifact intake: disk + memory capture from the same case in one hallway run
- DFRWS 2008 benchmark (memory + pcap combined)
- Public SIFT demo AMI with Terry holdout pre-mounted — one command to reproduce any result

**Medium term**
- **Proactive threat hunting:** instead of "investigate this image," give the agent a network segment and let it find which endpoints show indicators. The room architecture extends naturally — Room 1 becomes live endpoint intake, Room A plans the hunt query, Room 2 executes against live data.
- **Web surface assessment:** OWASP-class active reconnaissance as a first-class room. The same harness discipline — sealed scope, plan before scan, every finding traceable — applied to web targets.
- **Cross-artifact correlation:** memory + disk + network from the same incident, cross-referenced automatically. If disk says one thing and memory says another, the agent catches it.

**Long term**
- The hallway as a community standard: open catalog format so the SIFT community can contribute SIFT tools and skills the same way they contribute tools to the workstation itself.

---

## Repository layout

```
cold-box/
├── LICENSE
├── README.md                        ← this file
├── docs/
│   ├── architecture.md
│   ├── PROJECT_STORY.md
│   ├── DATASETS.md
│   ├── ACCURACY.md
│   └── submission-logs/
│       ├── README.md
│       ├── layer1_analyst_log.excerpt.md
│       └── layer2_analyst_log.excerpt.md
└── cold-box-room/
    ├── pyproject.toml
    ├── designnew.md                 ← hallway spec
    ├── cold_box_room/
    │   ├── r1/                      ← intake, seal, evidence, hallway state
    │   ├── planning/                ← guard, models, scoring, markdown, plan_py
    │   ├── r2/                      ← sandbox, executor, audit, security
    │   ├── agent/                   ← prompts, situation, tools
    │   ├── mcp/                     ← MCP server, handlers, register
    │   ├── skills/                  ← executor, manifest
    │   ├── room_3/                  ← skill dispatch, checkpoint, analyst log
    │   └── e2e/                     ← hallway entry points, benchmarks
    ├── tools/manifest.json          ← SIFT-234 catalog
    ├── skills/manifest.json         ← SKILL-171 runnable catalog
    ├── scripts/score_e2e_accuracy.py
    └── tests/                       ← 183 pytest cases
```

---

## Evidence integrity — summary

| Stage | Control | Validated |
|-------|---------|-----------|
| Intake | Staged copy, never original | ✅ `test_evidence_intake.py` |
| Seal | Read-only chmod + manifest | ✅ `test_r1_table.py` |
| Room 1 lock | `return_to_room("1")` → hard error | ✅ `test_hallway_flow.py` |
| Sandbox | Working copy — originals untouched | ✅ sandbox materialise test |
| Tool execution | Catalog IDs only, no free shell | ✅ executor security tests |
| Output scope | Scratch-only writes, blocked destructive flags | ✅ `test_executor_security.py` |
| Logbooks | Harness-owned, agent cannot append | ✅ tool log tests |
| Audit trail | `audit_id` per run, append-only | ✅ audit chain tests |

---

## License

MIT — Copyright © 2026 [at-src](https://github.com/at-src).
