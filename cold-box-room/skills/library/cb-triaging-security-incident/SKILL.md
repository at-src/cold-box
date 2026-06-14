---
name: cb-triaging-security-incident
skill_id: cb-triaging-security-incident
journal_id: CB-SKL-114
description: Cold-box analyst playbook — Triaging Security Incident. Performs initial
  triage of security incidents to determine severity, scope, and required response
  actions using the NIST SP 800-61r3 and SANS PICERL frameworks. Classifies incidents
  by type, assigns priority based on business impact, and ro
domain: cold-box
subdomain: incident-response
tier: core
case_profiles:
- windows_disk
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- incident-triage
- NIST-800-61
- SANS-PICERL
- severity-classification
- SOC-operations
cold_box_version: 2
inspired_by: triaging-security-incident
---

# Triaging Security Incident (cold-box)

> **Journal ID:** `CB-SKL-114` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-114`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-triaging-security-incident")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-triaging-security-incident")` → note **`CB-SKL-114`**
2. `log_skill(case_id, journal_id="CB-SKL-114", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-114` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- A SIEM or EDR alert fires and requires human classification before escalation
- Multiple concurrent alerts arrive and the SOC must prioritize response order
- An end user reports suspicious activity and the incident needs initial categorization
- A threat intelligence feed matches an IOC observed in the environment

## Tool map (SIFT via MCP)

**Execution mode:** `partial` — Tools mapped but some are unavailable — check `describe_sift_tool` / `list_sift_tools`.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-114] powershell per playbook step",
  "why": "Executing cb-triaging-security-incident \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-114` (`cb-triaging-security-incident`)

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

- A SIEM or EDR alert fires and requires human classification before escalation
- Multiple concurrent alerts arrive and the SOC must prioritize response order
- An end user reports suspicious activity and the incident needs initial categorization
- A threat intelligence feed matches an IOC observed in the environment

**Do not use** for routine vulnerability scanning results or compliance audit findings that do not represent active security incidents.

## Prerequisites

- Access to SIEM platform (Splunk, Elastic, Microsoft Sentinel) with current alert data
- Incident classification taxonomy aligned to NIST SP 800-61r3 categories
- Predefined severity matrix mapping asset criticality to threat type
- Contact roster for escalation paths (Tier 1 through Tier 3 and CIRT)
- Asset inventory with business criticality ratings

## Workflow

### Step 1: Collect Initial Alert Data

Gather all available context from the triggering alert before making classification decisions:

- **Alert source**: Which detection system generated the alert (EDR, SIEM, IDS/IPS, firewall, user report)
- **Timestamp**: When the event occurred and when it was detected (dwell time gap)
- **Affected assets**: Hostnames, IP addresses, user accounts involved
- **Alert fidelity**: Historical true-positive rate for this detection rule
- **Raw evidence**: Log entries, packet captures, process execution chains

```
Example SIEM alert context:
Source:       CrowdStrike Falcon
Detection:    Suspicious PowerShell Execution (T1059.001)
Host:         WORKSTATION-FIN-042
User:         jsmith@corp.example.com
Timestamp:    2025-11-15T14:23:17Z
Severity:     High (detection rule confidence: 92%)
Process:      powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...
Parent:       outlook.exe (PID 4812)
```

### Step 2: Classify the Incident Type

Map the alert to a standard incident category per NIST SP 800-61r3:

| Category | Examples |
|----------|----------|
| Unauthorized Access | Compromised credentials, privilege escalation, IDOR |
| Denial of Service | Volumetric DDoS, application-layer flood, resource exhaustion |
| Malicious Code | Malware execution, ransomware detonation, cryptominer |
| Improper Usage | Policy violation, insider data exfiltration, shadow IT |
| Reconnaissance | Port scanning, directory enumeration, credential spraying |
| Web Application Attack | SQL injection, XSS, SSRF exploitation |

### Step 3: Assign Severity Using Impact Matrix

Calculate severity by combining asset criticality with threat severity:

```
Severity = f(Asset Criticality, Threat Type, Data Sensitivity, Lateral Movement Potential)

Critical (P1): Crown jewel systems compromised, active data exfiltration, ransomware spreading
High (P2):     Production system compromise, confirmed malware execution, privileged account takeover
Medium (P3):   Non-production compromise, unsuccessful exploitation attempt, single endpoint malware
Low (P4):      Reconnaissance activity, policy violation, benign true positive
```

Response SLA targets:
- P1: Acknowledge within 15 minutes, containment within 1 hour
- P2: Acknowledge within 30 minutes, containment within 4 hours
- P3: Acknowledge within 2 hours, investigation within 24 hours
- P4: Acknowledge within 8 hours, investigation within 72 hours

### Step 4: Perform Initial Enrichment

Before escalation, enrich the alert with contextual data:

- **Threat intelligence**: Check IOCs (IP, hash, domain) against TI platforms (VirusTotal, OTX, MISP)
- **Asset context**: Query CMDB for asset owner, business function, data classification
- **User context**: Check identity provider for recent authentication anomalies, MFA status
- **Historical correlation**: Search for related alerts on the same host/user in the past 30 days
- **Network context**: Verify if source/destination IPs are internal, known partners, or external threat actors

### Step 5: Document and Escalate

Create a structured triage record and route to the appropriate response tier:

```
Incident Triage Record
━━━━━━━━━━━━━━━━━━━━━
Ticket ID:       INC-2025-1547
Triage Analyst:  [analyst name]
Triage Time:     2025-11-15T14:35:00Z (12 min from alert)
Classification:  Malicious Code - Macro-based initial access
Severity:        P2 - High
Affected Assets: WORKSTATION-FIN-042 (Finance dept, handles PII)
Affected Users:  jsmith@corp.example.com
IOCs Identified: powershell.exe spawned by outlook.exe, encoded command
TI Matches:      Base64 payload matches known Qakbot loader pattern
Escalation:      Tier 2 - Malware IR team
Recommended:     Isolate endpoint, preserve memory dump, block sender domain
```

### Step 6: Initiate Containment Hold

If severity is P1 or P2, initiate immediate containment actions while awaiting full investigation:

- Network-isolate the affected endpoint via EDR (CrowdStrike contain, Defender isolate)
- Disable compromised user accounts in Active Directory or identity provider
- Block identified malicious IPs/domains at firewall and DNS sinkhole
- Preserve volatile evidence (memory dump) before any remediation

## Key Concepts

| Term | Definition |
|------|------------|
| **Triage** | Rapid assessment process to classify and prioritize security incidents based on severity and business impact |
| **PICERL** | SANS incident response framework: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned |
| **Dwell Time** | Duration between initial compromise and detection; average is 10 days per Mandiant M-Trends 2025 |
| **True Positive Rate** | Percentage of alerts from a detection rule that represent genuine security incidents |
| **Crown Jewel Assets** | Systems and data critical to business operations whose compromise would cause severe organizational impact |
| **Alert Fatigue** | Degraded analyst performance caused by high volumes of low-fidelity or false-positive alerts |
| **Mean Time to Acknowledge (MTTA)** | Average time from alert generation to analyst acknowledgment; key SOC performance metric |

## Tools & Systems

- **Splunk Enterprise Security**: SIEM platform for alert aggregation, correlation, and triage workflow management
- **CrowdStrike Falcon**: EDR platform providing endpoint telemetry, detection, and one-click host containment
- **TheHive**: Open-source incident response platform for case management, task tracking, and team collaboration
- **MISP**: Threat intelligence sharing platform for IOC enrichment during triage
- **Cortex XSOAR**: SOAR platform for automating enrichment playbooks and triage decision trees

## Common Scenarios

### Scenario: Encoded PowerShell from Email Client

**Context**: SOC analyst receives a P2 alert showing `powershell.exe` with a Base64-encoded command spawned as a child process of `outlook.exe` on a finance department workstation.

**Approach**:
1. Decode the Base64 payload to determine the command intent
2. Check the parent process chain for anomalies (Outlook spawning PowerShell is abnormal)
3. Query VirusTotal for the decoded payload hash
4. Correlate with email gateway logs to identify the triggering email and sender
5. Check if other recipients in the organization received the same email
6. Isolate the endpoint and escalate to Tier 2 with full triage context

**Pitfalls**:
- Dismissing encoded PowerShell as a false positive without decoding the payload
- Failing to check for lateral spread to other recipients of the same phishing email
- Remediating the endpoint before capturing volatile memory evidence

## Output Format

```
INCIDENT TRIAGE REPORT
======================
Ticket:          INC-[YYYY]-[NNNN]
Date/Time:       [ISO 8601 timestamp]
Triage Analyst:  [Name]
Time to Triage:  [minutes from alert to classification]

CLASSIFICATION
Type:            [NIST category]
Severity:        [P1-P4] - [Critical/High/Medium/Low]
Confidence:      [High/Medium/Low]
MITRE ATT&CK:   [Technique ID and name]

AFFECTED SCOPE
Assets:          [hostname(s), IP(s)]
Users:           [account(s)]
Data at Risk:    [classification level]
Business Unit:   [department]

EVIDENCE SUMMARY
[Bullet list of key observations]

ENRICHMENT RESULTS
TI Matches:      [Yes/No - details]
Historical:      [Related prior incidents]
Asset Criticality: [rating]

RECOMMENDED ACTIONS
1. [Immediate action]
2. [Investigation step]
3. [Escalation target]

ESCALATION
Routed To:       [Team/Individual]
SLA Target:      [Containment deadline]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
