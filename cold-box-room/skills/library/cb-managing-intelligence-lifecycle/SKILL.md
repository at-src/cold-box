---
name: cb-managing-intelligence-lifecycle
skill_id: cb-managing-intelligence-lifecycle
journal_id: CB-SKL-300
description: Cold-box analyst playbook — Managing Intelligence Lifecycle. Manages
  the end-to-end cyber threat intelligence lifecycle from planning and direction through
  collection, processing, analysis, dissemination, and feedback to ensure intelligence
  products meet stakeholder requirements and continuously impr
domain: cold-box
subdomain: threat-intelligence
tier: adjacent
case_profiles:
- threat_intel
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- CTI
- intelligence-lifecycle
- PIR
- NIST-SP-800-150
- threat-intelligence-program
- NIST-CSF
cold_box_version: 2
inspired_by: managing-intelligence-lifecycle
---

# Managing Intelligence Lifecycle (cold-box)

> **Journal ID:** `CB-SKL-300` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-300`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-managing-intelligence-lifecycle")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-managing-intelligence-lifecycle")` → note **`CB-SKL-300`**
2. `log_skill(case_id, journal_id="CB-SKL-300", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-300` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Establishing a formal CTI program and defining its operational model
- Conducting quarterly intelligence requirements reviews with business stakeholders
- Evaluating CTI program maturity against established frameworks (FIRST CTI-SIG maturity model)

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — procedure steps target external platforms (SIEM, cloud, etc.).
Use for investigation guidance; log `{journal_id}` and note gaps when SIFT cannot run a step.

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

_No SIFT tools mapped for this playbook on cold-box._
Follow the procedure for reasoning; document external-platform gaps in the journal.

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-300` (`cb-managing-intelligence-lifecycle`)

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

Use this skill when:
- Establishing a formal CTI program and defining its operational model
- Conducting quarterly intelligence requirements reviews with business stakeholders
- Evaluating CTI program maturity against established frameworks (FIRST CTI-SIG maturity model)

**Do not use** this skill for day-to-day IOC triage or incident-specific intelligence tasks — those use operational intelligence workflows, not lifecycle management.

## Prerequisites

- Executive sponsorship and defined CTI team structure (1+ dedicated analysts)
- Stakeholder map identifying intelligence consumers (SOC, IR, executive team, vulnerability management)
- Existing feed subscriptions or ISAC memberships for collection baseline
- CTI platform (MISP, ThreatConnect, OpenCTI) for lifecycle management

## Workflow

### Step 1: Planning and Direction

Define Priority Intelligence Requirements (PIRs) with stakeholders:
- Interview SOC leads, IR team, CISO, risk management, and product security
- Document PIRs in structured format: "What is the current capability and intent of [threat actor] to attack [critical asset] using [technique]?"
- Prioritize 5–10 PIRs for the quarter, reviewed monthly

Example PIR: "Is ransomware group Cl0p currently targeting organizations in our sector using MoveIT or GoAnywhere vulnerabilities?"

### Step 2: Collection Planning

Map PIRs to required collection sources:
- Technical sources: commercial feeds, TAXII, ISAC data, honeypot telemetry, darkweb monitoring
- Human sources: vendor threat briefings, industry working groups, law enforcement partnerships
- Internal sources: SIEM logs, EDR telemetry, phishing submission mailbox

Document collection gaps and associated costs to fill them.

### Step 3: Processing and Normalization

Implement automated processing pipeline:
- Ingest → normalize to STIX 2.1 → deduplicate → enrich → score confidence
- Reject unverifiable or duplicate indicators before analysis
- Tag all processed data with source, collection date, and expiration

### Step 4: Analysis and Production

Produce intelligence at three levels:
- **Strategic**: Quarterly threat landscape report for executives; sector trends, geopolitical context
- **Operational**: Weekly campaign reports for security leadership; active campaigns, adversary activity
- **Tactical**: Daily IOC bulletins for SOC; actionable indicators with block/monitor recommendations

Apply structured analytic techniques: Analysis of Competing Hypotheses (ACH), Key Assumptions Check, Devil's Advocacy.

### Step 5: Dissemination

Match product format to audience:
- Executives: 1-page PDF with risk ratings, business impact, recommended decisions
- SOC analysts: SIEM-ready IOC list, Sigma rules, MISP events
- Vulnerability management: CVE lists with EPSS scores and exploitation likelihood
- IT/Security leadership: Full intelligence report with technical appendix

Apply TLP classifications and distribution lists per product type.

### Step 6: Feedback and Evaluation

Collect feedback within 5 business days of dissemination:
- Did the product address the PIR?
- Was actionability sufficient?
- What data was missing?

Track metrics quarterly: PIR coverage rate, IOC true positive rate, time-to-disseminate, stakeholder satisfaction score (NPS or structured survey).

## Key Concepts

| Term | Definition |
|------|-----------|
| **PIR** | Priority Intelligence Requirement — specific, actionable question driving intelligence collection and analysis |
| **Intelligence Lifecycle** | Six-phase iterative process: Planning → Collection → Processing → Analysis → Dissemination → Feedback |
| **Strategic Intelligence** | Long-term threat trend analysis for executive decision-making; time horizon 6–24 months |
| **Operational Intelligence** | Campaign-level analysis for security program decisions; time horizon 1–6 months |
| **Tactical Intelligence** | Specific IOCs and TTPs for immediate detection and blocking; time horizon hours to days |
| **FIRST CTI-SIG** | Forum of Incident Response and Security Teams — CTI Special Interest Group maturity model |

## Tools & Systems

- **ThreatConnect**: TIP with built-in intelligence lifecycle workflows, PIR tracking, and stakeholder reporting dashboards
- **MISP**: Open-source TIP supporting intelligence lifecycle from collection through sharing
- **OpenCTI**: Graph-based CTI platform with workflow management for intelligence products
- **Recorded Future**: Commercial platform with structured intelligence reports aligned to the intelligence lifecycle

## Common Pitfalls

- **Collection without direction**: Ingesting every available feed without PIRs produces data overload and no actionable intelligence.
- **Missing feedback loops**: Without structured feedback, CTI teams produce reports that don't meet stakeholder needs and lose organizational relevance.
- **Tactical-only focus**: Overemphasis on IOC sharing neglects strategic intelligence that informs security investment and risk decisions.
- **No metrics program**: Cannot demonstrate CTI program value without tracking detection contributions, true positive rates, and stakeholder satisfaction.
- **Underfunded collection**: PIRs cannot be answered without appropriate collection sources; document and escalate gaps rather than producing low-confidence estimates.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
