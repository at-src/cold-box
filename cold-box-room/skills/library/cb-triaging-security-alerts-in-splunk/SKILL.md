---
name: cb-triaging-security-alerts-in-splunk
skill_id: cb-triaging-security-alerts-in-splunk
journal_id: CB-SKL-336
description: 'Cold-box analyst playbook — Triaging Security Alerts In Splunk. Triages
  security alerts in Splunk Enterprise Security by classifying severity, investigating
  notable events, correlating related telemetry, and making escalation or closure
  decisions using SPL queries and the Incident Review dashboard. Use '
domain: cold-box
subdomain: soc-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- soc
- splunk
- alert-triage
- siem
- notable-events
- correlation-search
- incident-review
cold_box_version: 2
inspired_by: triaging-security-alerts-in-splunk
---

# Triaging Security Alerts In Splunk (cold-box)

> **Journal ID:** `CB-SKL-336` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-336`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-triaging-security-alerts-in-splunk")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-triaging-security-alerts-in-splunk")` → note **`CB-SKL-336`**
2. `log_skill(case_id, journal_id="CB-SKL-336", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-336` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- SOC Tier 1 analysts need to process the Incident Review queue in Splunk Enterprise Security (ES)
- Notable events require rapid severity classification and initial investigation before escalation
- Alert volume exceeds capacity and analysts need a systematic triage methodology
- Management requests metrics on alert disposition (true positive, false positive, benign)

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `head` | `SIFT-011` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-336] head per playbook step",
  "why": "Executing cb-triaging-security-alerts-in-splunk \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-336] sort per playbook step",
  "why": "Executing cb-triaging-security-alerts-in-splunk \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-336` (`cb-triaging-security-alerts-in-splunk`)

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
- SOC Tier 1 analysts need to process the Incident Review queue in Splunk Enterprise Security (ES)
- Notable events require rapid severity classification and initial investigation before escalation
- Alert volume exceeds capacity and analysts need a systematic triage methodology
- Management requests metrics on alert disposition (true positive, false positive, benign)

**Do not use** for deep forensic investigation — escalate to Tier 2/3 after initial triage confirms malicious activity.

## Prerequisites

- Splunk Enterprise Security 7.x+ with Incident Review dashboard configured
- CIM-normalized data sources (Windows Event Logs, firewall, proxy, endpoint)
- Role with `ess_analyst` capability for notable event status updates
- Familiarity with SPL (Search Processing Language)

## Workflow

### Step 1: Access Incident Review and Prioritize Queue

Open the Incident Review dashboard in Splunk ES. Sort notable events by urgency (calculated from severity x priority). Apply filters to focus on unassigned events:

```spl
| `notable`
| search status="new" OR status="unassigned"
| sort - urgency
| table _time, rule_name, src, dest, user, urgency, status
| head 50
```

Focus on Critical and High urgency events first. Group related alerts by `src` or `dest` to identify attack chains rather than treating each alert independently.

### Step 2: Investigate the Notable Event Context

For each notable event, pivot to raw events. Example for a brute force alert:

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
src_ip="192.168.1.105"
earliest=-1h latest=now
| stats count by src_ip, dest, user, status
| where count > 10
| sort - count
```

Check if the source IP is internal (lateral movement) or external (perimeter attack). Cross-reference with asset and identity lookups:

```spl
| `notable`
| search rule_name="Brute Force Access Behavior Detected"
| lookup asset_lookup_by_cidr ip AS src OUTPUT category, owner, priority
| lookup identity_lookup_expanded identity AS user OUTPUT department, managedBy
| table _time, src, dest, user, category, owner, department
```

### Step 3: Correlate Across Data Sources

Check if the same source appears in other telemetry:

```spl
index=proxy OR index=firewall src="192.168.1.105" earliest=-24h
| stats count by index, sourcetype, action, dest_port
| sort - count
```

Look for corroborating evidence: Did the same IP also trigger DNS anomalies, proxy blocks, or endpoint detection alerts?

```spl
index=main sourcetype="cisco:asa" src="192.168.1.105" action=blocked earliest=-24h
| timechart span=1h count by dest_port
```

### Step 4: Check Threat Intelligence Enrichment

Query the threat intelligence framework for known IOCs:

```spl
| `notable`
| search search_name="Threat - Threat Intelligence Match - Rule"
| lookup threat_intel_by_ip ip AS src OUTPUT threat_collection, threat_description, threat_key
| table _time, src, dest, threat_collection, threat_description, weight
| where weight >= 3
```

For domains, check against threat lists:

```spl
| tstats count from datamodel=Web where Web.url="*evil-domain.com*" by Web.src, Web.url, Web.status
| rename Web.* AS *
```

### Step 5: Classify and Disposition the Alert

Update the notable event status in Incident Review:

| Disposition | Criteria | Action |
|-------------|----------|--------|
| **True Positive** | Corroborating evidence confirms malicious activity | Escalate to Tier 2, create incident ticket |
| **Benign True Positive** | Alert fired correctly but activity is authorized (e.g., pen test) | Close with comment, add suppression if recurring |
| **False Positive** | Alert logic matched benign behavior | Close, tune correlation search, document pattern |
| **Undetermined** | Insufficient data to classify | Assign to Tier 2 with investigation notes |

Update via Splunk ES UI or REST API:

```spl
| sendalert update_notable_event param.status="2" param.urgency="critical"
  param.comment="Confirmed brute force from compromised workstation. Escalated to IR-2024-0431."
  param.owner="analyst_jdoe"
```

### Step 6: Document Triage Findings

Record in the notable event comment field:
- Source/destination involved
- Data sources examined
- Correlation findings (related alerts, TI matches)
- Disposition rationale
- Next steps for escalation

```spl
| `notable`
| search rule_name="Brute Force*" status="closed"
| stats count by status_label, disposition
| addtotal
```

### Step 7: Track Triage Metrics

Monitor triage performance over time:

```spl
| `notable`
| where status_end > 0
| eval triage_time = status_end - _time
| stats avg(triage_time) AS avg_triage_sec, median(triage_time) AS med_triage_sec,
        count by rule_name, status_label
| eval avg_triage_min = round(avg_triage_sec/60, 1)
| sort - count
| table rule_name, status_label, count, avg_triage_min
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Notable Event** | Splunk ES alert generated by a correlation search that meets defined risk or threshold criteria |
| **Urgency** | Calculated field combining event severity with asset/identity priority (Critical/High/Medium/Low/Informational) |
| **Correlation Search** | Scheduled SPL query that detects threat patterns and generates notable events when conditions match |
| **CIM** | Common Information Model — Splunk's normalized field naming convention enabling cross-source queries |
| **Disposition** | Final classification of an alert: true positive, false positive, benign true positive, or undetermined |
| **MTTD/MTTR** | Mean Time to Detect / Mean Time to Respond — key SOC metrics measuring detection and resolution speed |

## Tools & Systems

- **Splunk Enterprise Security**: SIEM platform providing Incident Review dashboard, correlation searches, and risk-based alerting
- **Splunk SOAR (Phantom)**: Orchestration platform for automating triage playbooks and enrichment actions
- **Asset & Identity Framework**: Splunk ES lookup tables mapping IPs to asset owners and users to departments for context enrichment
- **Threat Intelligence Framework**: Splunk ES module ingesting STIX/TAXII feeds and matching IOCs against notable events

## Common Scenarios

- **Brute Force Alerts**: Correlate EventCode 4625 (failed logon) with 4624 (successful logon) from same source to determine if attack succeeded
- **Malware Detection**: Cross-reference endpoint AV alert with proxy logs for C2 callback confirmation
- **Data Exfiltration Alert**: Check outbound data volume from DLP and proxy logs against user baseline
- **Privilege Escalation**: Correlate EventCode 4672 (special privileges assigned) with 4720 (account created) from non-admin users
- **Lateral Movement**: Map EventCode 4648 (explicit credential logon) across multiple destinations from single source

## Output Format

```
TRIAGE REPORT — Notable Event #NE-2024-08921
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Alert:        Brute Force Access Behavior Detected
Time:         2024-03-15 14:23:07 UTC
Source:       192.168.1.105 (WORKSTATION-042, Finance Dept)
Destination:  10.0.5.20 (DC-PRIMARY, Domain Controller)
User:         jsmith (Finance Analyst)

Investigation:
  - 847 failed logons (4625) in 12 minutes from src
  - Successful logon (4624) at 14:35:02 after brute force
  - No proxy/DNS anomalies from src in prior 24h
  - Source not on threat intel lists

Disposition:  TRUE POSITIVE — Compromised credential
Action:       Escalated to Tier 2, ticket IR-2024-0431 created
              Account jsmith disabled pending password reset
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
