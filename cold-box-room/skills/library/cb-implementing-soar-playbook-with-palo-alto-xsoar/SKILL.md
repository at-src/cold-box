---
name: cb-implementing-soar-playbook-with-palo-alto-xsoar
skill_id: cb-implementing-soar-playbook-with-palo-alto-xsoar
journal_id: CB-SKL-062
description: Cold-box analyst playbook — Implementing Soar Playbook With Palo Alto
  Xsoar. Implement automated incident response playbooks in Cortex XSOAR to orchestrate
  security workflows across SOC tools and reduce manual response time.
domain: cold-box
subdomain: soc-operations
tier: core
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- xsoar
- soar
- palo-alto
- playbook
- automation
- incident-response
- orchestration
- cortex
cold_box_version: 2
inspired_by: implementing-soar-playbook-with-palo-alto-xsoar
---

# Implementing Soar Playbook With Palo Alto Xsoar (cold-box)

> **Journal ID:** `CB-SKL-062` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-062`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-soar-playbook-with-palo-alto-xsoar")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-soar-playbook-with-palo-alto-xsoar")` → note **`CB-SKL-062`**
2. `log_skill(case_id, journal_id="CB-SKL-062", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-062` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing soar playbook with palo alto xsoar capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-062] file per playbook step",
  "why": "Executing cb-implementing-soar-playbook-with-palo-alto-xsoar \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-062` (`cb-implementing-soar-playbook-with-palo-alto-xsoar`)

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

Cortex XSOAR (formerly Demisto) is Palo Alto Networks' Security Orchestration, Automation, and Response platform. Playbooks are the core automation engine in XSOAR, enabling SOC teams to automate repetitive incident response tasks. XSOAR provides 900+ prebuilt integration packs, 87 common playbooks, and a visual drag-and-drop editor for building custom workflows. Organizations using SOAR automation reduce mean time to respond (MTTR) by 80% on average.


## When to Use

- When deploying or configuring implementing soar playbook with palo alto xsoar capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Cortex XSOAR deployed (version 8.x or later, or XSOAR hosted)
- Administrative access for playbook creation
- Integration packs installed for relevant security tools
- Incident types and layouts configured
- API access to external tools (SIEM, EDR, TI platforms, ticketing)

## Playbook Architecture

### XSOAR Component Hierarchy

```
Incident Type (e.g., Phishing)
    |
    v
Incident Layout (UI display configuration)
    |
    v
Pre-Processing Rules (auto-classification, deduplication)
    |
    v
Playbook (automation logic)
    |-- Sub-Playbooks (modular reusable workflows)
    |-- Tasks (individual automation steps)
    |-- Conditional Tasks (decision branches)
    |-- Scripts (custom Python/JavaScript)
    |-- Integrations (external tool commands)
    |
    v
War Room (investigation timeline)
    |
    v
Closing Report
```

### Playbook Task Types

| Task Type | Purpose | Example |
|---|---|---|
| Standard | Execute a command | `!ip ip=8.8.8.8` |
| Conditional | Branch logic | If severity > high, escalate |
| Manual | Require analyst input | Approve containment action |
| Section Header | Organize workflow | "Enrichment Phase" |
| Data Collection | Gather external data | Ask user for additional details |
| Timer | Wait for condition/time | Wait 5 minutes then check |

## Building a Phishing Response Playbook

### Step 1: Define Incident Type

```yaml
incident_type: Phishing
playbook: Phishing Investigation - Full
severity_mapping:
  - condition: email contains executable attachment
    severity: high
  - condition: email from external domain with link
    severity: medium
  - condition: email reported by user
    severity: low
layout: Phishing Layout
sla: 60 minutes
```

### Step 2: Playbook YAML Structure

```yaml
id: phishing-investigation-full
version: -1
name: Phishing Investigation - Full
description: Automated phishing email investigation with enrichment, analysis, and response
starttaskid: "0"
tasks:
  "0":
    id: "0"
    taskid: start
    type: start
    nexttasks:
      '#none#':
      - "1"
  "1":
    id: "1"
    taskid: extract-indicators
    type: regular
    task:
      name: Extract Indicators from Email
      script: ParseEmailFiles
    nexttasks:
      '#none#':
      - "2"
      - "3"
      - "4"
  "2":
    id: "2"
    taskid: enrich-urls
    type: playbook
    task:
      name: URL Enrichment
      playbookName: URL Enrichment - Generic v2
  "3":
    id: "3"
    taskid: enrich-files
    type: playbook
    task:
      name: File Enrichment
      playbookName: File Enrichment - Generic v2
  "4":
    id: "4"
    taskid: enrich-ips
    type: playbook
    task:
      name: IP Enrichment
      playbookName: IP Enrichment - Generic v2
  "5":
    id: "5"
    taskid: determine-verdict
    type: condition
    task:
      name: Is Email Malicious?
    conditions:
      - label: "yes"
        condition:
          - - operator: isEqualString
              left: DBotScore.Score
              right: "3"
      - label: "no"
    nexttasks:
      "yes":
      - "6"
      "no":
      - "9"
  "6":
    id: "6"
    taskid: block-sender
    type: regular
    task:
      name: Block Sender Domain
      script: '|||o365-mail-block-sender'
    scriptarguments:
      sender_address: ${incident.emailfrom}
  "7":
    id: "7"
    taskid: search-mailboxes
    type: regular
    task:
      name: Search and Delete from All Mailboxes
      script: '|||o365-mail-purge-compliance-search'
    scriptarguments:
      query: "from:${incident.emailfrom} subject:${incident.emailsubject}"
  "8":
    id: "8"
    taskid: notify-user
    type: regular
    task:
      name: Notify Reporting User
      script: '|||send-mail'
    scriptarguments:
      to: ${incident.reporter}
      subject: "Phishing Report Confirmed - Action Taken"
      body: "The email you reported has been confirmed as malicious and removed."
  "9":
    id: "9"
    taskid: close-incident
    type: regular
    task:
      name: Close Incident
      script: closeInvestigation
```

### Step 3: Integration Commands

#### Email Analysis
```
!ParseEmailFiles entryid=${File.EntryID}
!rasterize url=${URL.Data} type=png
```

#### Threat Intelligence Enrichment
```
!url url=${URL.Data}
!file file=${File.SHA256}
!ip ip=${IP.Address}
!domain domain=${Domain.Name}
```

#### Containment Actions
```
!o365-mail-block-sender sender=${incident.emailfrom}
!o365-mail-purge-compliance-search query="from:${incident.emailfrom}"
!pan-os-block-ip ip=${IP.Address} log_forwarding="default"
!cortex-xdr-isolate-endpoint endpoint_id=${Endpoint.ID}
```

#### Ticketing Integration
```
!jira-create-issue summary="Phishing Incident - ${incident.id}" type="Incident" priority="High"
!servicenow-create-ticket short_description="Security Incident" urgency="2"
```

## Common SOC Playbook Templates

### 1. Malware Investigation Playbook

```
Trigger: Malware alert from EDR
Steps:
  1. Extract file hash, process details, host info
  2. Enrich hash via VirusTotal, Hybrid Analysis
  3. Check if file is on allowlist
  4. If malicious:
     a. Isolate endpoint via EDR
     b. Block hash on all endpoints
     c. Search for hash across environment
     d. Create incident ticket
  5. If clean: Close as false positive
```

### 2. Account Compromise Playbook

```
Trigger: Impossible travel or suspicious login alert
Steps:
  1. Get user details from Active Directory
  2. Get login history for past 30 days
  3. Check for impossible travel (geo-distance vs time)
  4. Check for known VPN/proxy IP
  5. If compromised:
     a. Disable AD account
     b. Revoke all OAuth tokens
     c. Reset MFA
     d. Notify user's manager
     e. Search for lateral movement
  6. If false positive: Document and close
```

### 3. DDoS Mitigation Playbook

```
Trigger: Network anomaly alert
Steps:
  1. Verify traffic spike from network monitoring
  2. Identify source IPs and geolocation
  3. Check if source IPs are known botnets
  4. Implement rate limiting on WAF
  5. If sustained attack:
     a. Enable upstream DDoS protection
     b. Activate CDN scrubbing
     c. Notify ISP if needed
  6. Monitor and document
```

## Custom XSOAR Scripts

### Python Automation Script Example

```python
# XSOAR Automation Script: CalculateRiskScore
def calculate_risk_score():
    """Calculate composite risk score for an incident."""
    severity = demisto.incident().get('severity', 0)
    indicator_count = len(demisto.get(demisto.context(), 'DBotScore', []))
    malicious_count = len([
        i for i in demisto.get(demisto.context(), 'DBotScore', [])
        if i.get('Score', 0) == 3
    ])

    base_score = severity * 20
    indicator_boost = min(indicator_count * 5, 25)
    malicious_boost = malicious_count * 15

    risk_score = min(100, base_score + indicator_boost + malicious_boost)

    return_results(CommandResults(
        outputs_prefix='RiskScore',
        outputs={'Score': risk_score, 'Level': 'Critical' if risk_score > 80 else 'High' if risk_score > 60 else 'Medium'},
        readable_output=f'Risk Score: {risk_score}/100'
    ))

calculate_risk_score()
```

## Playbook Performance Metrics

| Metric | Before SOAR | After SOAR | Improvement |
|---|---|---|---|
| Phishing MTTR | 45 min | 5 min | 89% reduction |
| Malware MTTR | 60 min | 8 min | 87% reduction |
| Account Compromise MTTR | 30 min | 4 min | 87% reduction |
| Alerts Handled per Shift | 50 | 200+ | 300% increase |
| False Positive Handling | 10 min | 30 sec | 95% reduction |

## References

- [Cortex XSOAR Playbooks Overview](https://xsoar.pan.dev/docs/playbooks/playbooks-overview)
- [From Zero to Process to XSOAR Playbook](https://live.paloaltonetworks.com/t5/community-blogs/from-zero-to-process-to-xsoar-playbook/ba-p/564568)
- [XSOAR Common Playbooks Pack](https://www.paloaltonetworks.com/blog/security-operations/playbook-of-the-week-xsoar-common-playbook/)
- [Cortex XSOAR Product Page](https://www.paloaltonetworks.com/cortex/cortex-xsoar)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
