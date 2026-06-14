---
name: cb-building-soc-escalation-matrix
skill_id: cb-building-soc-escalation-matrix
journal_id: CB-SKL-144
description: Cold-box analyst playbook — Building Soc Escalation Matrix. Build a structured
  SOC escalation matrix defining severity tiers, response SLAs, escalation paths,
  and notification procedures for security incidents.
domain: cold-box
subdomain: soc-operations
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- soc
- escalation
- incident-management
- severity
- sla
- triage
- tiered-soc
cold_box_version: 2
inspired_by: building-soc-escalation-matrix
---

# Building Soc Escalation Matrix (cold-box)

> **Journal ID:** `CB-SKL-144` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-144`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-building-soc-escalation-matrix")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-building-soc-escalation-matrix")` → note **`CB-SKL-144`**
2. `log_skill(case_id, journal_id="CB-SKL-144", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-144` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring building soc escalation matrix capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `cut` | `SIFT-006` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `cut` → `SIFT-006`

```json
{
  "tool_id": "SIFT-006",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-144] cut per playbook step",
  "why": "Executing cb-building-soc-escalation-matrix \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-144` (`cb-building-soc-escalation-matrix`)

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

## Overview

A SOC escalation matrix defines how security incidents move through the organization based on severity, impact, and response requirements. Modern SOCs use context-driven escalation combining business risk, asset criticality, and data sensitivity rather than purely severity-based models. Organizations using AI and automation in their SOC cut detection-and-containment lifecycle to approximately 161 days, an 80-day improvement over the 241-day industry average.


## When to Use

- When deploying or configuring building soc escalation matrix capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with soc operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## SOC Tier Structure

### Tier 1 - Alert Triage Analyst
- Monitors SIEM dashboards and alert queues
- Performs initial alert classification (true/false positive)
- Handles P3 and P4 incidents to resolution
- Escalates P1 and P2 incidents to Tier 2 within SLA
- Documents initial findings in ticketing system

### Tier 2 - Incident Analyst
- Performs deep-dive investigation on escalated incidents
- Conducts root cause analysis and scoping
- Executes containment procedures
- Handles P2 incidents to resolution
- Escalates P1 incidents to Tier 3 or management

### Tier 3 - Senior Analyst / Threat Hunter
- Handles P1 critical incidents and APT investigations
- Performs proactive threat hunting
- Develops detection rules and playbooks
- Conducts malware reverse engineering
- Leads incident response for major breaches

### Management Escalation
- SOC Manager: Operational decisions, resource allocation
- CISO: Business impact decisions, executive communication
- Legal/PR: Data breach notification, media response
- External IR: Third-party incident response engagement

## Severity Classification

### P1 - Critical

| Attribute | Value |
|---|---|
| Impact | Active data breach, ransomware spreading, critical systems compromised |
| Business Impact | Revenue loss, regulatory exposure, customer data at risk |
| Initial Response | 15 minutes |
| Escalation to Tier 2 | Immediate |
| Escalation to Management | 30 minutes |
| Resolution Target | 4 hours |
| Communication | Every 30 minutes to stakeholders |
| Examples | Active ransomware, confirmed data exfiltration, domain admin compromise |

### P2 - High

| Attribute | Value |
|---|---|
| Impact | Confirmed compromise, limited scope, no active exfiltration |
| Business Impact | Potential revenue impact, contained risk |
| Initial Response | 30 minutes |
| Escalation to Tier 2 | 30 minutes if unresolved |
| Escalation to Management | 2 hours |
| Resolution Target | 8 hours |
| Communication | Every 2 hours to SOC management |
| Examples | Compromised user account, malware on single endpoint, insider threat indicator |

### P3 - Medium

| Attribute | Value |
|---|---|
| Impact | Suspicious activity requiring investigation |
| Business Impact | Low immediate risk |
| Initial Response | 4 hours |
| Escalation to Tier 2 | 8 hours if unresolved |
| Resolution Target | 24 hours |
| Communication | Daily status update |
| Examples | Policy violation, failed brute force, suspicious email report |

### P4 - Low

| Attribute | Value |
|---|---|
| Impact | Informational alerts, routine security events |
| Business Impact | Minimal |
| Initial Response | 8 hours |
| Escalation | Only if pattern emerges |
| Resolution Target | 72 hours |
| Communication | Weekly summary |
| Examples | Vulnerability scan findings, expired certificates, policy exceptions |

## Escalation Decision Matrix

```
                    Asset Criticality
                    Low        Medium      High        Critical
Severity  Low      P4         P4          P3          P3
          Medium   P4         P3          P2          P2
          High     P3         P2          P2          P1
          Critical P2         P1          P1          P1
```

## Context-Driven Escalation Triggers

### Automatic Escalation (no analyst decision needed)

| Trigger | Action |
|---|---|
| Ransomware detected on any endpoint | P1 - Immediate Tier 3 + Management |
| Domain admin account compromise | P1 - Immediate Tier 3 + Management |
| Active data exfiltration to external IP | P1 - Immediate Tier 3 + Management |
| Critical infrastructure (DC, SCADA) alert | P1 - Immediate Tier 2 minimum |
| Executive account anomaly | P2 - Immediate Tier 2 |
| Multiple hosts with same malware | P1 - Immediate Tier 2 |

### Time-Based Escalation

| Condition | Action |
|---|---|
| P2 unresolved after 4 hours | Escalate to Tier 3 |
| P3 unresolved after 12 hours | Escalate to Tier 2 |
| Any incident unresolved past SLA | Escalate to SOC Manager |
| P1 unresolved after 2 hours | Escalate to CISO |

## Communication Templates

### P1 Initial Notification

```
SUBJECT: [P1 CRITICAL] Security Incident - {Incident_ID}

Incident Summary:
- Type: {incident_type}
- Affected Systems: {systems}
- Affected Users: {users}
- Current Status: {status}
- Assigned To: {analyst}

Impact Assessment:
- Business Impact: {impact}
- Data at Risk: {data_risk}
- Containment Status: {containment}

Next Actions:
- {action_1}
- {action_2}

Next Update: {time} (30-minute intervals)
Bridge Line: {conference_details}
```

## Escalation Matrix Implementation

### SOAR Integration

```yaml
# XSOAR escalation playbook trigger
trigger:
  condition: incident.severity == "critical" AND incident.asset_criticality == "high"
  action:
    - assign_tier: 3
    - notify: [soc_manager, ciso]
    - create_war_room: true
    - start_bridge: true
    - set_sla: 4h

auto_escalation_rules:
  - name: P2 Time-Based Escalation
    condition: incident.severity == "high" AND incident.age > 4h AND incident.status != "resolved"
    action:
      - escalate_tier: 3
      - notify: soc_manager
      - add_comment: "Auto-escalated due to SLA breach"
```

## References

- [Torq - Threat Escalation Matrix for Modern Security Challenges](https://torq.io/blog/escalation-matrix/)
- [ClearFeed - Incident Escalation Matrix](https://clearfeed.ai/blogs/incident-escalation-matrix)
- [Vectra - SOC Operations Guide](https://www.vectra.ai/topics/soc-operations)
- [Runframe - Incident Priority Levels Explained](https://runframe.io/learn/incident-priority)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
