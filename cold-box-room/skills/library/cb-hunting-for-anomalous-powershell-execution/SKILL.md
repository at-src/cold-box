---
name: cb-hunting-for-anomalous-powershell-execution
skill_id: cb-hunting-for-anomalous-powershell-execution
journal_id: CB-SKL-047
description: Cold-box analyst playbook — Hunting For Anomalous Powershell Execution.
  Hunt for malicious PowerShell activity by analyzing Script Block Logging (Event
  4104), Module Logging (Event 4103), and process creation events. The analyst parses
  Windows Event Log EVTX files to detect obfuscated commands, AMSI bypass atte
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- windows_disk
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- powershell
- script-block-logging
- event-4104
- amsi
- threat-hunting
- evtx
- obfuscation
cold_box_version: 2
inspired_by: hunting-for-anomalous-powershell-execution
---

# Hunting For Anomalous Powershell Execution (cold-box)

> **Journal ID:** `CB-SKL-047` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-047`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-anomalous-powershell-execution")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-anomalous-powershell-execution")` → note **`CB-SKL-047`**
2. `log_skill(case_id, journal_id="CB-SKL-047", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-047` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for anomalous powershell execution
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

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
  "purpose": "[CB-SKL-047] powershell per playbook step",
  "why": "Executing cb-hunting-for-anomalous-powershell-execution \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-047` (`cb-hunting-for-anomalous-powershell-execution`)

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

PowerShell Script Block Logging (Event ID 4104) records the full deobfuscated script text
executed on a Windows endpoint, making it the primary data source for hunting malicious
PowerShell. Combined with Module Logging (4103) and process creation events, analysts can
detect encoded commands, AMSI bypass patterns, download cradles, credential theft tools,
and fileless attack techniques even when the attacker uses obfuscation layers.


## When to Use

- When investigating security incidents that require hunting for anomalous powershell execution
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Windows Event Log exports (.evtx) from Microsoft-Windows-PowerShell/Operational
- Python 3.8+ with python-evtx and lxml libraries
- Script Block Logging enabled via Group Policy
- Understanding of common PowerShell attack techniques

## Steps

1. Parse EVTX files extracting Event 4104 script block text and metadata
2. Reassemble multi-part script blocks using ScriptBlock ID correlation
3. Scan script text for AMSI bypass indicators and obfuscation patterns
4. Detect encoded command execution and base64 payloads
5. Identify download cradles, credential dumping, and lateral movement commands
6. Score and prioritize findings by threat severity

## Expected Output

```json
{
  "total_events": 1247,
  "suspicious_events": 23,
  "amsi_bypass_attempts": 2,
  "encoded_commands": 8,
  "download_cradles": 5,
  "credential_access": 3
}
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
