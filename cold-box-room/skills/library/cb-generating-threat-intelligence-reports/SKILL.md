---
name: cb-generating-threat-intelligence-reports
skill_id: cb-generating-threat-intelligence-reports
journal_id: CB-SKL-224
description: Cold-box analyst playbook — Generating Threat Intelligence Reports. Generates
  structured cyber threat intelligence reports at strategic, operational, and tactical
  levels tailored to specific audiences including executives, security operations
  teams, and technical analysts. Use when producing finished intell
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
- threat-intelligence
- intelligence-products
- TLP
- PIR
- report-writing
- NIST-CSF
cold_box_version: 2
inspired_by: generating-threat-intelligence-reports
---

# Generating Threat Intelligence Reports (cold-box)

> **Journal ID:** `CB-SKL-224` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-224`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-generating-threat-intelligence-reports")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-generating-threat-intelligence-reports")` → note **`CB-SKL-224`**
2. `log_skill(case_id, journal_id="CB-SKL-224", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-224` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Producing weekly, monthly, or quarterly threat intelligence summaries for security leadership
- Creating a rapid intelligence assessment in response to a breaking threat (e.g., new zero-day, active ransomware campaign)
- Generating sector-specific threat briefings for executive decision-making on security investments

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — Limited SIFT coverage; treat remaining steps as reference.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `yara` | `SIFT-045` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-224] yara per playbook step",
  "why": "Executing cb-generating-threat-intelligence-reports \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-224` (`cb-generating-threat-intelligence-reports`)

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
- Producing weekly, monthly, or quarterly threat intelligence summaries for security leadership
- Creating a rapid intelligence assessment in response to a breaking threat (e.g., new zero-day, active ransomware campaign)
- Generating sector-specific threat briefings for executive decision-making on security investments

**Do not use** this skill for raw IOC distribution — use TIP/MISP for automated IOC sharing and reserve report generation for analyzed, finished intelligence.

## Prerequisites

- Completed analysis from collection and processing phase (PIRs partially or fully answered)
- Audience profile: technical level, decision-making authority, information classification clearance
- TLP classification decision for the product
- Organization-specific reporting template aligned to audience expectations

## Workflow

### Step 1: Determine Report Type and Audience

Select the appropriate intelligence product type:

**Strategic Intelligence Report**: For C-suite, board, risk committee
- Content: Threat landscape trends, adversary intent vs. capability, risk to business objectives
- Format: 1–3 pages, minimal jargon, business impact language, recommended decisions
- Frequency: Monthly/Quarterly

**Operational Intelligence Report**: For CISO, security directors, IR leads
- Content: Active campaigns, adversary TTPs, defensive recommendations, sector peer incidents
- Format: 3–8 pages, moderate technical detail, mitigation priority list
- Frequency: Weekly

**Tactical Intelligence Bulletin**: For SOC analysts, threat hunters, vulnerability management
- Content: Specific IOCs, YARA rules, Sigma detections, CVEs, patching guidance
- Format: Structured tables, code blocks, 1–2 pages
- Frequency: Daily or as-needed

**Flash Report**: Urgent notification for imminent or active threats
- Content: What is happening, immediate risk, what to do right now
- Format: 1 page maximum, distributed within 2 hours of threat identification
- Frequency: As-needed (zero-day, active campaign targeting sector)

### Step 2: Structure Report Using Intelligence Standards

Apply intelligence writing standards from government and professional practice:

**Headline/Key Judgment**: Lead with the most important finding in plain language.
- Bad: "This report examines threat actor TTPs associated with Cl0p ransomware"
- Good: "Cl0p ransomware group is actively exploiting CVE-2024-20353 in Cisco ASA devices to gain initial access; organizations using unpatched ASA appliances face imminent ransomware risk"

**Confidence Qualifiers** (use language from DNI ICD 203):
- High confidence: "assess with high confidence" — strong evidence, few assumptions
- Medium confidence: "assess" — credible sources but analytical assumptions required
- Low confidence: "suggests" — limited sources, significant uncertainty

**Evidence Attribution**: Cite sources using reference numbers [1], [2]; maintain source anonymization in TLP:AMBER/RED products.

### Step 3: Write Report Body

Use structured format:

**Executive Summary** (3–5 bullet points): Key findings, immediate business risk, top recommended action

**Threat Overview**: Who is the adversary? What is their objective? Why does this matter to us?

**Technical Analysis**: TTPs with ATT&CK technique IDs, IOCs, observed campaign behavior

**Impact Assessment**: Potential operational, financial, reputational impact if attack succeeds

**Recommended Actions**: Prioritized, time-bound defensive measures with owner assignment

**Appendices**: Full IOC lists, YARA rules, Sigma detections, raw source references

### Step 4: Apply TLP and Distribution Controls

Select TLP based on source sensitivity and sharing agreements:
- **TLP:RED**: Named recipients only; cannot be shared outside briefing room
- **TLP:AMBER+STRICT**: Organization only; no sharing with subsidiaries or partners
- **TLP:AMBER**: Organization and trusted partners with need-to-know
- **TLP:GREEN**: Community-wide sharing (ISAC members, sector peers)
- **TLP:WHITE/CLEAR**: Public distribution; no restrictions

Include TLP watermark on every page header and footer.

### Step 5: Review and Quality Control

Before dissemination, apply these checks:
- **Accuracy**: Are all facts sourced and cited? No unsubstantiated claims.
- **Clarity**: Can the target audience understand this without additional context?
- **Actionability**: Does every report section drive a decision or action?
- **Classification**: Is TLP correctly applied? No source identification in AMBER/RED products?
- **Timeliness**: Is this intelligence still current? Events older than 48 hours require freshness assessment.

## Key Concepts

| Term | Definition |
|------|-----------|
| **Finished Intelligence** | Analyzed, contextualized intelligence product ready for consumption by decision-makers; distinct from raw collected data |
| **Key Judgment** | Primary analytical conclusion of a report; clearly stated in opening paragraph |
| **TLP** | Traffic Light Protocol — FIRST-standard classification system for controlling intelligence sharing scope |
| **ICD 203** | Intelligence Community Directive 203 — US government standard for analytic standards including confidence language |
| **Flash Report** | Urgent, time-sensitive intelligence notification for imminent threats; prioritizes speed over depth |
| **Intelligence Gap** | Area where collection is insufficient to answer a PIR; should be explicitly documented in reports |

## Tools & Systems

- **ThreatConnect Reports**: Built-in report templates with ATT&CK mapping, IOC tables, and stakeholder distribution controls
- **Recorded Future**: Pre-built intelligence report templates with automated sourcing from proprietary datasets
- **OpenCTI Reports**: STIX-based report objects with linked entities for structured finished intelligence
- **Microsoft Word/Confluence**: Common report delivery formats; use organization-approved templates with TLP headers

## Common Pitfalls

- **Writing for analysts instead of the audience**: Technical detail appropriate for SOC analysts overwhelms executives. Maintain strict audience segmentation.
- **Omitting confidence levels**: Statements presented without confidence qualifiers appear as established facts when they may be low-confidence assessments.
- **Intelligence without recommendations**: Reports that describe threats without prescribing actions leave stakeholders without direction.
- **Stale intelligence**: Publishing a report on a threat campaign that was resolved 2 weeks ago creates alarm without utility. Include freshness dating on all claims.
- **Over-classification**: Applying TLP:RED to information that could be TLP:GREEN impedes community sharing and limits defensive value across the sector.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
