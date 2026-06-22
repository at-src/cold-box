# Project story (Devpost)

Copy/adapt into your [Devpost submission](https://findevil.devpost.com/).

---

## Inspiration

Forensic investigators repeat the same Sleuth Kit workflows case after case. Agentic DFIR prototypes often collapse planning, execution, and reporting into one chat — mixing guesses with evidence. We built cold-box-room to **inherit cold-box discipline**: seal the table, plan on paper, execute with proof, self-correct without reopening the evidence bag.

---

## What it does

Autonomous analyst for the SANS SIFT Workstation. Five hallway rooms — seal, plan extraction, run **234 SIFT tools**, plan analysis, run **213 skill playbooks** — producing Layer 1 and Layer 2 write-ups. Every tool run gets an `audit_id` in `audit.jsonl`; plan steps cannot pass without proof.

**Measured on real images:** Terry USB holdout **100%** benchmark accuracy in ~16 min; NIST CFReDS Data Leakage PC **100%** required checks in ~18 min.

---

## How we built it

Deterministic hallway state machine with harness-gated promotion. Per-room tool schemas via `planning/guard.py`. Catalog-driven SIFT executor — sandbox in, scratch out, sanitized CLI. Skill runtime routes nested tools through the same audit chain. Parallel tool dispatch in Room 2. Keyword benchmarks with staging scope validation.

---

## Challenges we solved

**Evidence intake at scale.** EWF auto-chain attaches E02–E04 from a single E01 path; directory intake stages full image folders. Scorer validates manifest scope so accuracy reflects staged evidence.

**Parallel plan execution.** File-locked `plan_a.py` / `plan_b.py` updates survive concurrent step marking during parallel SIFT dispatch.

**Production runtime.** Prompt caching and stat-only R1 hashing deliver full hallway runs in ~16–18 minutes on holdout and NIST PC cases.

---

## Accomplishments we're proud of

- Full hallway E2E: R1 → A → 2 → B → 3 — **183 automated tests**
- Architectural room guards + sealed R1 + scratch-only executor
- **234 SIFT + 213 skills** in committed catalogs
- **100% Terry holdout** · **100% NDLC required checks**
- Traceable audit trail: analyst log → `audit_id` → scratch stdout

---

## What we learned

Phase separation beats longer system prompts. `return_to_room` with mandatory corrections delivers real self-correction on the record. Evidence integrity is architectural — seal, sandbox copy, harness logbooks.

---

## What's next

Multi-artifact DFRWS intake, SHA-256-chained audit, public SIFT demo AMI with Terry holdout pre-mounted.

---

## Built with

Python 3.10+ · Anthropic Claude (Sonnet) · SANS SIFT / Sleuth Kit · pytest · MCP

---

## Autonomous execution

| Challenge | Our approach |
|-----------|--------------|
| Tool sprawl | SIFT-### / SKILL-### catalogs |
| Skipping methodology | Room A/B planning gates |
| Untraceable findings | audit.jsonl + proof-gated plans |
| Self-correction | return_to_room + corrections field |
| Scored accuracy | Keyword benchmarks + staging scope |
