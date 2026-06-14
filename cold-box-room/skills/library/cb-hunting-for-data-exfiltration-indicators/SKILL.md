---
name: cb-hunting-for-data-exfiltration-indicators
skill_id: cb-hunting-for-data-exfiltration-indicators
journal_id: CB-SKL-230
description: Cold-box analyst playbook — Hunting For Data Exfiltration Indicators.
  Hunt for data exfiltration through network traffic analysis, detecting unusual data
  flows, DNS tunneling, cloud storage uploads, and encrypted channel abuse.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- mitre-attack
- data-exfiltration
- dlp
- network-analysis
- proactive-detection
cold_box_version: 2
inspired_by: hunting-for-data-exfiltration-indicators
---

# Hunting For Data Exfiltration Indicators (cold-box)

> **Journal ID:** `CB-SKL-230` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-230`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-data-exfiltration-indicators")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-data-exfiltration-indicators")` → note **`CB-SKL-230`**
2. `log_skill(case_id, journal_id="CB-SKL-230", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-230` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for data theft in compromised environments
- After detecting unusual outbound data volumes or patterns
- When investigating potential insider threat data theft
- During incident response to determine what data was stolen
- When threat intel indicates data exfiltration campaigns targeting your sector

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `zeek` | `SIFT-119` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-230] zeek per playbook step",
  "why": "Executing cb-hunting-for-data-exfiltration-indicators \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-230] file per playbook step",
  "why": "Executing cb-hunting-for-data-exfiltration-indicators \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-230` (`cb-hunting-for-data-exfiltration-indicators`)

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

- When hunting for data theft in compromised environments
- After detecting unusual outbound data volumes or patterns
- When investigating potential insider threat data theft
- During incident response to determine what data was stolen
- When threat intel indicates data exfiltration campaigns targeting your sector

## Prerequisites

- Network proxy/firewall logs with byte-level data transfer metrics
- DLP solution or CASB with cloud upload visibility
- DNS query logs for DNS exfiltration detection
- Email gateway logs for attachment monitoring
- SIEM with data volume anomaly detection capabilities

## Workflow

1. **Define Exfiltration Channels**: Identify potential channels (HTTP/S uploads, DNS tunneling, email attachments, cloud storage, removable media, encrypted protocols).
2. **Baseline Normal Data Flows**: Establish baseline outbound data transfer volumes per user, host, and destination over a 30-day window.
3. **Detect Volume Anomalies**: Identify hosts or users transferring significantly more data than baseline to external destinations.
4. **Analyze Transfer Destinations**: Check destination domains/IPs against threat intel, identify newly registered domains, personal cloud storage, and foreign infrastructure.
5. **Inspect Protocol Abuse**: Look for DNS tunneling (large/frequent TXT queries), ICMP tunneling, or data hidden in allowed protocols.
6. **Correlate with File Access**: Link exfiltration indicators to file access events on sensitive file shares, databases, or repositories.
7. **Report and Contain**: Document findings with evidence, estimate data exposure, and recommend containment actions.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1041 | Exfiltration Over C2 Channel |
| T1048 | Exfiltration Over Alternative Protocol |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 |
| T1567 | Exfiltration Over Web Service |
| T1567.002 | Exfiltration to Cloud Storage |
| T1052 | Exfiltration Over Physical Medium |
| T1029 | Scheduled Transfer |
| T1030 | Data Transfer Size Limits (staging) |
| T1537 | Transfer Data to Cloud Account |
| T1020 | Automated Exfiltration |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Splunk | SIEM for data volume analysis and SPL queries |
| Zeek | Network metadata for data flow analysis |
| Microsoft Defender for Cloud Apps | CASB for cloud exfiltration |
| Netskope | Cloud DLP and exfiltration detection |
| Suricata | Network IDS for protocol anomaly detection |
| RITA | DNS exfiltration and beacon detection |
| ExtraHop | Network traffic analysis for data flow |

## Common Scenarios

1. **Cloud Storage Exfiltration**: User uploads sensitive documents to personal Google Drive or Dropbox via browser.
2. **DNS Tunneling**: Malware exfiltrates data encoded in DNS subdomain queries to attacker-controlled nameserver.
3. **HTTPS Upload**: Compromised system POSTs large data blobs to C2 server over encrypted HTTPS.
4. **Email Attachment Exfiltration**: Insider forwards sensitive documents to personal email accounts.
5. **Staging and Compression**: Adversary stages data in compressed archives before slow exfiltration to avoid detection.

## Output Format

```
Hunt ID: TH-EXFIL-[DATE]-[SEQ]
Exfiltration Channel: [HTTP/DNS/Email/Cloud/USB]
Source: [Host/User]
Destination: [Domain/IP/Service]
Data Volume: [Bytes/MB/GB]
Time Period: [Start - End]
Protocol: [HTTPS/DNS/SMTP/SMB]
Files Involved: [Count/Types]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
