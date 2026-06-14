---
name: cb-detecting-rdp-brute-force-attacks
skill_id: cb-detecting-rdp-brute-force-attacks
journal_id: CB-SKL-029
description: Cold-box analyst playbook — Detecting Rdp Brute Force Attacks. Detect
  RDP brute force attacks by analyzing Windows Security Event Logs for failed authentication
  patterns (Event ID 4625), successful logons after failures (Event ID 4624), NLA
  failures, and source IP frequency analysis.
domain: cold-box
subdomain: threat-detection
tier: core
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-detection
- rdp
- brute-force
- windows-event-logs
- blue-team
- siem
cold_box_version: 2
inspired_by: detecting-rdp-brute-force-attacks
---

# Detecting Rdp Brute Force Attacks (cold-box)

> **Journal ID:** `CB-SKL-029` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-029`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-rdp-brute-force-attacks")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-rdp-brute-force-attacks")` → note **`CB-SKL-029`**
2. `log_skill(case_id, journal_id="CB-SKL-029", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-029` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting rdp brute force attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — Limited SIFT coverage; treat remaining steps as reference.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `wevtutil` | `SIFT-185` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `wevtutil` → `SIFT-185`

```json
{
  "tool_id": "SIFT-185",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-029] wevtutil per playbook step",
  "why": "Executing cb-detecting-rdp-brute-force-attacks \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-029` (`cb-detecting-rdp-brute-force-attacks`)

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

RDP brute force attacks target Windows Remote Desktop Protocol services by attempting rapid credential guessing against exposed RDP endpoints. Detection relies on analyzing Windows Security Event Logs for Event ID 4625 (failed logon with Logon Type 10 or 3) and correlating with Event ID 4624 (successful logon) to identify compromised accounts. This skill covers parsing EVTX files with python-evtx, identifying attack patterns through source IP frequency analysis, detecting NLA bypass attempts, and generating actionable detection reports.


## When to Use

- When investigating security incidents that require detecting rdp brute force attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `python-evtx`, `lxml` libraries
- Windows Security EVTX log files (exported from Event Viewer or collected via WEF)
- Understanding of Windows authentication Event IDs (4624, 4625, 4776)
- Familiarity with RDP Logon Types (Type 3 for NLA, Type 10 for RemoteInteractive)

## Steps

### Step 1: Export Security Event Logs
Export Windows Security logs to EVTX format using Event Viewer or wevtutil:
```
wevtutil epl Security C:\logs\security.evtx
```

### Step 2: Parse Failed Logon Events
Use python-evtx to parse Event ID 4625 entries, extracting source IP, target username, failure reason (Sub Status), and Logon Type fields.

### Step 3: Analyze Attack Patterns
Identify brute force patterns by:
- Counting failed logons per source IP within time windows
- Detecting username spray attacks (many usernames from one IP)
- Correlating 4625 failures with subsequent 4624 success from same IP

### Step 4: Generate Detection Report
Produce a JSON report with top attacking IPs, targeted accounts, time-based analysis, and compromise indicators.

## Expected Output

JSON report containing:
- Total failed logon events and unique source IPs
- Top attacking IPs ranked by failure count
- Targeted usernames and failure sub-status codes
- Successful logons following brute force attempts (potential compromises)
- Time-series analysis of attack intensity

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
