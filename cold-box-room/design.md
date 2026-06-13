# Cold-box hallway design

Deterministic rooms. Harness enforces promotion. Agent cannot skip rooms.

## Agent vs harness (scores and status)

| Field | Who sets it | Solid wall? |
|-------|-------------|-------------|
| **Self-score** (1–10) | **Agent** | No — agent states it; harness only checks threshold (> 8) |
| **Plan score** (%) | **Harness** | Yes — computed from step outcomes; agent cannot override |
| **Step status** (passed / fail / not_relevant / held_for_later) | **Harness** | Yes — written to `plan.py` by harness from rules + proof; agent does not self-assign **passed** |

Agent writes **findings**, **why**, and **self-score** in analyst logs. Harness writes tool logs, **plan score**, and **step status**.

---

## Room 1 (R1) — Staging area

**What this room is**

Raw uploads only. Whatever the user drops in (via UI or CLI) lands in the **R1 staging area** first — full original files as received (E01, AFF, RAM, zip, etc.). Not extracted artifacts, not parsed output, not scratch.

Any case (Jo, Charlie, etc.) starts here. R2 and later rooms never receive direct user uploads.

**Layout**

- One case directory under the R1 staging root (`r1-staging/{case_id}/`).
- After intake, evidence is **sealed read-only** (chmod; optional immutable flag).

**Checkpoint (must pass to enter Room 2)**

1. **File present** — at least one evidence file in R1 staging for this case.
2. **File not empty** — that file has non-zero size.

Both must be true. If either fails, stay in R1.

**Sealing (hardcoded, not agent choice)**

- Evidence is read-only after seal.
- No writes, deletes, or in-place changes on staged files.
- Harness enforces seal; agent does not unseal.
- Reads after seal go through the staging read channel only.

**Promotion**

```
if staging_has_file AND file_not_empty:
    → Room 2
else:
    → remain in R1
```

Nothing else is required in R1.

---

## Room 2 (R2) — Layer 1 evidence extraction

**What this room is**

Evidence is extracted here from the R1 staging area using SIFT tools (Layer 2). Raw files stay sealed in R1; R2 reads through the staging read channel and writes output to scratch — extracted material, not new user uploads.

**Tools**

- SIFT tools live in this room.
- Full tool definitions are **not** preloaded. Agent requests catalog on demand (`list_sift_tools`, `describe_sift_tool`, etc.).
- Every extraction runs through a **strict harness call** (Python dispatch → audited tool run). No manual re-implementation outside that path.

**Logs (opens in R2 — two files, not one)**

Layer 1 uses **separate files** so tool noise does not mix with agent prose.

| File | Writer | Contents |
|------|--------|----------|
| **Tool log** | Harness only (automatic) | Each SIFT run: command, extracted output / scratch ref, audit id, exit status. Agent never writes here. |
| **Analyst log** | Agent only | End-of-layer write-up (see below). Harness never appends tool rows here. |

Both files sit under the case/session record. Heading for the analyst log section: **Layer 1 — Evidence extraction**.

**Agent write-up (mandatory before R3)**

At the end of Layer 1, agent writes **only** in the **analyst log**. All three required:

1. **Findings** — what matters from the extractions  
2. **Self-score** — 1–10 for Layer 1 work (**agent stated**)  
3. **Why** — rationale for the score (and gaps if any)

No promotion without all three present. Only **self-score** is subjective; extraction success (checkpoint 1) is harness-verified.

**Checkpoint (must pass to enter Room 3)**

All of the following:

1. **At least one successful extraction** — harness recorded ≥1 tool run with `exit_code == 0` and non-empty scratch output this session in R2 (tool log).
2. **Agent Layer 1 write-up complete** — analyst log contains **findings + score + why** (all mandatory).
3. **Self-score > 8** — agent’s stated Layer 1 self-score strictly above 8 (9 or 10).

**If score ≤ 8**

- Door to R3 stays closed.
- Agent may keep using tools and retry the analyst log write-up (findings + score + why).
- **Three promotion attempts** max (harness counts attempts when agent submits Layer 1 write-up but score ≤ 8, write-up incomplete, or extraction gate fails).
- After 3 failed attempts: agent may write **why it cannot score above 8** and **exit** (case ends in R2; no R3). Harness records the reason.

**Promotion**

```
if successful_extraction_count >= 1
   AND analyst_log_has_findings AND analyst_log_has_score AND analyst_log_has_why
   AND agent_layer1_score > 8:
    → Room 3
elif promotion_attempts >= 3:
    → exit with documented reason (no R3)
else:
    → remain in R2 (more tool work / retry write-up)
```

---

## Room 3 (R3) — Planning

**What this room is**

Planning only. No analysis execution here. Agent reads what R2 extracted (tool log + scratch + Layer 1 analyst log), browses available skills/tools, and writes **how** it will approach Layer 2 analysis.

**What agent does**

1. Read the evidence from R2 (extracted scratch, tool log, analyst findings).
2. Browse skills catalog on demand (`list_skills_index`, `get_skill`, etc.) — pick what it **intends** to use per step. Tool/skill choice is not locked in R3; agent must look and decide, then record intent in the plan.
3. Write **`plan.md`** — strict plan: numbered steps, each step with **reason** why it is needed.
4. Write **`plan.py`** — same plan cemented as executable structure (numbered steps 1, 2, 3, …). Each step slot is ready for status updates in R4 (see below).

Harness does not verify that the agent “really” read every skill; browsing is expected. R4 will enforce execution against the plan.

**`plan.py` step statuses (harness-owned in R4)**

Each plan step ends in one of four states. **Harness sets status** in `plan.py` from deterministic rules — not agent self-report.

| Status | Meaning | Score |
|--------|---------|-------|
| **passed** | Harness verified proof (audit / scratch) for this step | **+1** |
| **fail** | Step abandoned or execution failed with no recovery | **−1** |
| **not_relevant** | Harness accepts drop — step removed from scoring pool | removed from total |
| **held_for_later** | Temporary defer while other steps run | **0** until resolved |

**Scoring pool**

If the plan has **N** steps, max achievable score is **N**, minimum is **−N**. Steps marked **not_relevant** are removed from N (they no longer count toward the pool). **held_for_later** stays in the pool until resolved in R4.

R3 only **defines** step slots in `plan.py`. **Status and plan score are applied in R4 by harness only.**

**Checkpoint (must pass to enter Room 4)**

All of the following:

1. **`plan.md` exists** — numbered steps, each with reason.
2. **`plan.py` exists** — same steps cemented (1, 2, 3, …), structure valid for status updates.
3. **Skills catalog consulted** — harness recorded ≥1 skills browse call this session in R3 (`list_skills_index` and/or `get_skill`). No proof that every skill was read; call happened.

**Promotion**

```
if plan_md_valid AND plan_py_valid AND skills_catalog_consulted:
    → Room 4
else:
    → remain in R3
```

Nothing is executed in R3 except reading evidence, browsing catalogs, and writing the two plan files.

---

## Room 4 (R4) — Layer 2 analysis (plan execution)

**What this room is**

Analysis on R2 evidence by **executing the R3 plan**. `plan.py` is the solid wall: nothing runs outside the plan. Agent works step-by-step (or in small parallel batches) until every step has a final status.

**Execution lock**

- Agent can **read the full plan** at all times.
- Agent may only **work on steps that are unlocked**:
  - Start at step **1** (lowest open step).
  - **Parallel:** up to **2 steps** at once. While those are in progress, no other steps until each active step gets a status.
  - After every active step receives a status, the next step(s) unlock (again max 2 in parallel).
- No skipping ahead. No ad-hoc work outside `plan.py` steps. Harness rejects tool/skill calls not tied to the current unlocked step(s).

**How a step runs**

- Each step runs through **strict harness execution** — skill playbooks via **`run_skill_script`** (`.py`), or tools as declared in that plan step.
- When work for a step completes (or is abandoned), **harness sets status** in `plan.py` before the next step(s) unlock:

| Status | Harness sets when |
|--------|-------------------|
| **passed** | Required proof exists for this step (audit id + scratch ref tied to step) |
| **fail** | Step abandoned, max retries exhausted, or tool run failed with no valid proof |
| **not_relevant** | Rules allow drop (e.g. evidence from prior step makes this step moot — harness validates) |
| **held_for_later** | Agent requested defer **and** harness allows; must resolve to passed / fail / not_relevant before R4 completes |

Agent cannot mark **passed** without harness proof. Agent cannot edit `plan.py` status directly.

**Logs (same split as R2 — Layer 2 heading)**

| File | Writer | Contents |
|------|--------|----------|
| **Tool log (L2)** | Harness only | Each plan-step tool/skill run: command, output/scratch ref, audit id, exit status, **plan step id**. |
| **Analyst log (L2)** | Agent only | End-of-room write-up (mandatory fields below). |

Heading: **Layer 2 — Analysis**.

**Agent write-up (mandatory before final output)**

At end of R4, agent writes in the **L2 analyst log**. All required:

1. **Findings** — analysis conclusions  
2. **Self-score** — 1–10 (**agent stated**)  
3. **Why** — rationale for self-score  
4. **Plan rating** — agent’s narrative summary (informational only; **does not affect plan score**)

**Plan score (harness only — deterministic)**

- Scoring pool = all plan steps **except** `not_relevant`.
- Each step contributes: **passed = +1**, **fail = −1**, **held_for_later** = unresolved until final status.
- **Plan score %** = `(passed_count / scoring_pool_size) × 100`  
  Computed only from **harness-set** statuses. Agent cannot change this number.

Minimum to leave R4: **plan score ≥ 70%** (harness gate).

**Checkpoint (must pass to write final output / enter Room 5)**

All of the following:

1. **Every plan step resolved** — each step has final status: **passed**, **fail**, or **not_relevant** (no open or permanent **held_for_later**).
2. **Plan score ≥ 70%** — harness-computed from deterministic step statuses.  
3. **Self-score > 8** — agent’s stated Layer 2 self-score strictly above 8 (9 or 10).
4. **L2 analyst log complete** — findings + self-score + why + plan rating (all mandatory).

Only then may agent write the **final case output** (report).

**If checkpoint not met**

- Agent may retry work within R4 (fix steps, re-run, update statuses and analyst log).
- **Three promotion attempts** max (harness counts when agent submits for final output but any gate fails).
- After 3 failed attempts: agent writes **why it cannot meet the gates** and **exits** (no final output). Harness records the reason.

**Promotion**

```
if all_steps_final_status
   AND plan_score_pct >= 70
   AND agent_layer2_self_score > 8
   AND analyst_log_l2_complete:
    → write final output (Room 5)
elif promotion_attempts >= 3:
    → exit with documented reason (no final output)
else:
    → remain in R4
```

---
