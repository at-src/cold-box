---
name: cb-powershell-empire-artifacts
skill_id: cb-powershell-empire-artifacts
journal_id: CB-SKL-101
description: Cold-box analyst playbook — Powershell Empire Artifacts. Detect PowerShell
  Empire framework artifacts in Windows event logs by identifying Base64 encoded launcher
  patterns, default user agents, staging URL structures, stager IOCs, and known Empire
  module signatures in Script Block Logging events.
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- PowerShell-Empire
- threat-hunting
- Script-Block-Logging
- base64
- stager
- C2
- MITRE-ATT&CK
- T1059.001
- forensics
cold_box_version: 2
inspired_by: analyzing-powershell-empire-artifacts
---

# Powershell Empire Artifacts (cold-box)

> **Journal ID:** `CB-SKL-101` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-101`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-powershell-empire-artifacts")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-powershell-empire-artifacts")` → note **`CB-SKL-101`**
2. `log_skill(case_id, journal_id="CB-SKL-101", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-101` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing powershell empire artifacts
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `strings` | `SIFT-044` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-101] powershell per playbook step",
  "why": "Executing cb-powershell-empire-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-101] strings per playbook step",
  "why": "Executing cb-powershell-empire-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-101` (`cb-powershell-empire-artifacts`)

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

PowerShell Empire is a post-exploitation framework consisting of listeners, stagers, and agents. Its artifacts leave detectable traces in Windows event logs, particularly PowerShell Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103). This skill analyzes event logs for Empire's default launcher string (`powershell -noP -sta -w 1 -enc`), Base64 encoded payloads containing `System.Net.WebClient` and `FromBase64String`, known module invocations (Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation), and staging URL patterns.


## When to Use

- When investigating security incidents that require analyzing powershell empire artifacts
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with access to Windows Event Log or exported EVTX files
- PowerShell Script Block Logging (Event ID 4104) enabled via Group Policy
- Module Logging (Event ID 4103) enabled for comprehensive coverage

## Key Detection Patterns

1. **Default launcher** — `powershell -noP -sta -w 1 -enc` followed by Base64 blob
2. **Stager indicators** — `System.Net.WebClient`, `DownloadData`, `DownloadString`, `FromBase64String`
3. **Module signatures** — Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation, Invoke-PSInject, Invoke-DCOM
4. **User agent strings** — default Empire user agents in HTTP listener configuration
5. **Staging URLs** — `/login/process.php`, `/admin/get.php` and similar default URI patterns

## Output

JSON report with matched IOCs, decoded Base64 payloads, timeline of suspicious events, MITRE ATT&CK technique mappings, and severity scores.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
