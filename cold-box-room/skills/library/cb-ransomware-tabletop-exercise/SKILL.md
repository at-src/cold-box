---
name: cb-ransomware-tabletop-exercise
skill_id: cb-ransomware-tabletop-exercise
journal_id: CB-SKL-318
description: Cold-box analyst playbook — Ransomware Tabletop Exercise. Plans and facilitates
  tabletop exercises simulating ransomware incidents to test organizational readiness,
  decision-making, and communication procedures. Designs realistic scenarios based
  on current ransomware threat actors (LockBit, ALPHV/
domain: cold-box
subdomain: ransomware-defense
tier: adjacent
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ransomware
- incident-response
- tabletop-exercise
- defense
- preparedness
cold_box_version: 2
inspired_by: performing-ransomware-tabletop-exercise
---

# Ransomware Tabletop Exercise (cold-box)

> **Journal ID:** `CB-SKL-318` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-318`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-ransomware-tabletop-exercise")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-ransomware-tabletop-exercise")` → note **`CB-SKL-318`**
2. `log_skill(case_id, journal_id="CB-SKL-318", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-318` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Testing organizational ransomware response procedures annually or after major infrastructure changes
- Validating decision-making processes for ransom payment, regulatory notification, and public disclosure
- Training executives, IT, legal, PR, and operations teams on their roles during a ransomware incident
- Meeting cyber insurance policy requirements for documented incident response testing
- Identifying gaps in recovery playbooks, communication plans, and backup procedures

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `handle` | `SIFT-178` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-318] handle per playbook step",
  "why": "Executing cb-ransomware-tabletop-exercise \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-318] file per playbook step",
  "why": "Executing cb-ransomware-tabletop-exercise \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-318` (`cb-ransomware-tabletop-exercise`)

- **action:** adopted | step | finding | deferred | completed
- **note:** What you did or concluded under this playbook
- **related_audit_ids:** (optional) CB-… from run_sift_tool
```

Or call MCP: `log_skill(case_id, journal_id="{journal_id}", action="adopted", note="...")`

## Cold-box path translation

When the procedure below uses host paths, translate as follows:

| Procedure path | Cold-box equivalent |
|----------------|---------------------|
| `C:\Evidence\...` / `/cases/...` | `{input_relpath}` on the sealed table (via viewport) |
| `C:\Output\...` / `/analysis/...` | `records/{case_id}/scratch/` (tool stdout/files) |
| Live SIEM / cloud console steps | **Reference only** on cold-box — note capability gap in journal |

Do not copy evidence off the table except into `records/{case_id}/scratch/` via `run_sift_tool`.


## Procedure

## When to Use

- Testing organizational ransomware response procedures annually or after major infrastructure changes
- Validating decision-making processes for ransom payment, regulatory notification, and public disclosure
- Training executives, IT, legal, PR, and operations teams on their roles during a ransomware incident
- Meeting cyber insurance policy requirements for documented incident response testing
- Identifying gaps in recovery playbooks, communication plans, and backup procedures

**Do not use** as a substitute for technical controls testing. Tabletop exercises validate procedures and decision-making, not technical detection or prevention capabilities.

## Prerequisites

- Documented incident response plan (IRP) that participants should have read before the exercise
- Identified exercise participants from: executive leadership, IT/security, legal, communications/PR, HR, operations, and external counsel
- Facilitator who is independent from the IR team (to provide objective evaluation)
- Ransomware scenario designed with injects that escalate over multiple rounds
- Evaluation criteria aligned to NIST CSF Respond/Recover functions
- Conference room or virtual meeting for 2-4 hours with no interruptions

## Workflow

### Step 1: Design the Exercise Scenario

Build a realistic scenario based on current threat actor TTPs:

**Scenario Structure:**
```
Phase 1: Initial Detection (30 min)
  - SOC receives alert for suspicious process execution on file server
  - EDR detects Cobalt Strike beacon on 3 workstations
  - Inject: External threat intel report links C2 IP to LockBit affiliate

Phase 2: Escalation (30 min)
  - Ransomware executes on 40% of servers during overnight hours
  - Ransom note demands $2M in Bitcoin with 72-hour deadline
  - Inject: Attackers contact media claiming data theft of customer PII

Phase 3: Decision Points (45 min)
  - Backup assessment reveals immutable copies are intact but primary backups encrypted
  - Legal advises on breach notification timeline (72 hours GDPR, varies by US state)
  - Inject: Threat actor publishes sample of stolen data on leak site

Phase 4: Recovery and Communication (45 min)
  - Recovery time estimate: 5-7 days from immutable backups
  - Insurance carrier engages negotiation firm
  - Inject: Major customer threatens contract termination without update within 24 hours
```

**Scenario Variables to Customize:**
- Threat actor group and known TTPs
- Percentage of infrastructure encrypted
- Whether backups are intact, partially compromised, or fully destroyed
- Type of data exfiltrated (PII, PHI, financial, trade secrets)
- Applicable regulatory frameworks (GDPR, HIPAA, PCI DSS, SEC rules)
- Ransom amount and payment deadline

### Step 2: Prepare Exercise Materials

Create the following documents for participants:

1. **Exercise Overview Briefing** - Ground rules, objectives, scope, and participants
2. **Situation Reports (SITREPs)** - One per phase, distributed as the exercise progresses
3. **Inject Cards** - New information introduced at specific times to force decision-making
4. **Decision Point Worksheets** - Structured forms for documenting group decisions
5. **Evaluation Scorecard** - Criteria for assessing response quality

**Key Decision Points to Include:**
- When to activate the incident response team
- Whether to shut down systems or contain selectively
- Whether to engage law enforcement (FBI IC3, CISA)
- Whether to pay the ransom and under what conditions
- When and how to notify regulators, customers, and the public
- How to prioritize system recovery order

### Step 3: Facilitate the Exercise

**Facilitator Responsibilities:**
- Present each phase scenario and distribute SITREPs
- Introduce injects at predetermined times to increase pressure
- Ask probing questions to test decision-making reasoning
- Ensure all participant groups contribute (prevent IT from dominating)
- Document all decisions, rationales, and action items
- Track time management (many teams lose time on early phases)

**Probing Questions by Phase:**

Phase 1 - Detection:
- Who makes the call to declare an incident? What criteria trigger it?
- How do we determine the scope of compromise from initial alerts?
- Do we have the forensic capability to investigate or do we need external help?

Phase 2 - Escalation:
- What is our communication plan for employees? Do they know not to turn on affected machines?
- Have we isolated the network to prevent further encryption?
- Who authorizes system shutdowns that impact business operations?

Phase 3 - Decision:
- Under what conditions would we consider paying the ransom?
- What are the legal obligations for notification at this point?
- How do we handle the public leak of customer data?

Phase 4 - Recovery:
- What is the recovery priority order? Is it documented or decided ad hoc?
- How long until critical business operations resume?
- What evidence preservation is required for law enforcement and insurance?

### Step 4: Evaluate and Score Responses

Score each functional area against defined criteria:

| Evaluation Area | Score (1-5) | Criteria |
|----------------|-------------|----------|
| Detection & Escalation | | Timely incident declaration, proper chain of command |
| Containment | | Network isolation, credential reset, scope assessment |
| Communication - Internal | | Employee notification, executive briefing, documented decisions |
| Communication - External | | Regulatory notification, customer communication, media response |
| Recovery Planning | | Backup verification, recovery priority, RTO tracking |
| Legal & Compliance | | Breach notification timelines, evidence preservation, law enforcement engagement |
| Business Continuity | | Manual operations, customer impact mitigation, revenue loss estimation |
| Payment Decision | | Structured framework, legal review, OFAC sanctions check |

### Step 5: Document Findings and Remediation Plan

Produce an after-action report (AAR) within 5 business days:

**AAR Contents:**
1. Exercise overview and objectives
2. Scenario summary and injects
3. Key decisions made and rationale
4. Strengths observed
5. Gaps identified with severity rating
6. Remediation actions with owners and deadlines
7. Comparison to previous exercise results (if applicable)

## Key Concepts

| Term | Definition |
|------|------------|
| **Tabletop Exercise (TTX)** | Discussion-based exercise where participants walk through a simulated incident scenario to test plans and procedures |
| **Inject** | New information introduced during the exercise to change the scenario and force additional decision-making |
| **SITREP** | Situation Report providing current status of the simulated incident at each exercise phase |
| **After-Action Report (AAR)** | Post-exercise document capturing findings, gaps, strengths, and remediation actions |
| **Double Extortion** | Ransomware tactic where attackers both encrypt data and threaten to publish stolen data unless ransom is paid |
| **OFAC Check** | Verification that ransom payment recipient is not on the US Treasury OFAC sanctions list, which would make payment illegal |

## Tools & Systems

- **CISA Tabletop Exercise Packages (CTEPs)**: Free scenario packages from CISA designed for critical infrastructure sectors
- **FEMA Homeland Security Exercise and Evaluation Program (HSEEP)**: Methodology for designing, conducting, and evaluating exercises
- **Immersive Labs**: Platform providing interactive cyber crisis simulations with real-time scoring
- **Tabletop Scenarios (from NCSC UK)**: Exercise in a Box tool providing free guided tabletop exercises
- **Ransomware Readiness Assessment (CISA)**: Self-assessment tool for evaluating ransomware preparedness

## Common Scenarios

### Scenario: Healthcare System Double Extortion Exercise

**Context**: A 5-hospital healthcare system conducts an annual ransomware tabletop. Previous exercise revealed gaps in HIPAA breach notification and clinical system recovery priority. This year's scenario simulates a double extortion attack targeting the EMR system.

**Approach**:
1. Design scenario based on Cl0p MOO (Managed Operations Operator) TTPs: exploitation of MOVEit vulnerability for initial access, data exfiltration of 500,000 patient records, followed by encryption of EMR database servers
2. Participants: CISO, CIO, CMO (Chief Medical Officer), General Counsel, VP Communications, Director of Clinical Operations, Privacy Officer, External IR firm representative
3. Phase 1 inject: EMR system down, emergency department diverting patients to neighboring hospital
4. Phase 2 inject: HHS OCR (Office for Civil Rights) contacts organization about reports of patient data on dark web
5. Phase 3 inject: Attacker provides decryption key sample for $3.5M, 48-hour deadline
6. Key finding: Organization lacks documented criteria for ransom payment decision and had not pre-identified an OFAC-compliant payment mechanism
7. Remediation: Establish payment decision framework, pre-engage ransomware negotiation firm, update HIPAA breach notification procedures with specific timelines

**Pitfalls**:
- Designing unrealistic scenarios that do not reflect actual ransomware TTPs, reducing exercise credibility
- Allowing technical teams to dominate the exercise while business and legal participants remain passive
- Not testing the communication plan (many organizations discover their notification list is outdated during the actual incident)
- Failing to follow up on remediation actions identified in the AAR, negating the exercise value

## Output Format

```
## Ransomware Tabletop Exercise - After Action Report

**Exercise Date**: [Date]
**Facilitator**: [Name]
**Scenario**: [Brief description]
**Duration**: [Hours]
**Participants**: [Count by department]

### Exercise Objectives
1. [Objective] - Met / Partially Met / Not Met
2. [Objective] - Met / Partially Met / Not Met

### Key Decisions Log
| Time | Decision Point | Decision Made | Rationale | Assessment |
|------|---------------|--------------|-----------|------------|

### Strengths Observed
1. [Strength]

### Gaps Identified
| Gap | Severity | Affected Area | Current State | Desired State |
|-----|----------|--------------|---------------|---------------|

### Remediation Actions
| Action | Owner | Deadline | Priority | Status |
|--------|-------|----------|----------|--------|

### Comparison to Previous Exercise
| Area | Previous Score | Current Score | Trend |
|------|---------------|--------------|-------|
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
