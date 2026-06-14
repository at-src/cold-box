---
name: cb-hunting-for-unusual-service-installations
skill_id: cb-hunting-for-unusual-service-installations
journal_id: CB-SKL-056
description: Cold-box analyst playbook — Hunting For Unusual Service Installations.
  Detect suspicious Windows service installations (MITRE ATT&CK T1543.003) by parsing
  System event logs for Event ID 7045, analyzing service binary paths, and identifying
  indicators of persistence mechanisms.
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- general
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- T1543.003
- service-installation
- persistence
- Event-7045
- Sysmon
- Windows-services
cold_box_version: 2
inspired_by: hunting-for-unusual-service-installations
---

# Hunting For Unusual Service Installations (cold-box)

> **Journal ID:** `CB-SKL-056` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-056`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-unusual-service-installations")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-unusual-service-installations")` → note **`CB-SKL-056`**
2. `log_skill(case_id, journal_id="CB-SKL-056", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-056` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for unusual service installations
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
  "purpose": "[CB-SKL-056] powershell per playbook step",
  "why": "Executing cb-hunting-for-unusual-service-installations \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-056` (`cb-hunting-for-unusual-service-installations`)

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

Attackers frequently install malicious Windows services for persistence and privilege escalation (MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service). Event ID 7045 in the System event log records every new service installation. This skill parses .evtx log files to extract service installation events, flags suspicious binary paths (temp directories, PowerShell, cmd.exe, encoded commands), and correlates with known attack patterns.


## When to Use

- When investigating security incidents that require hunting for unusual service installations
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `python-evtx`, `lxml`
- Windows System event log (.evtx) files
- Access to live System event log (optional, for real-time monitoring)
- Sysmon logs for enhanced process tracking (optional)

## Steps

1. Parse System.evtx for Event ID 7045 (new service installed)
2. Extract service name, binary path, service type, and account
3. Flag services with suspicious binary paths (temp dirs, encoded commands)
4. Detect PowerShell-based service creation patterns
5. Identify services running as LocalSystem with unusual paths
6. Cross-reference with known legitimate service baselines
7. Generate threat hunting report with MITRE ATT&CK T1543.003 mapping

## Expected Output

- JSON report listing all new service installations with risk scores, suspicious indicators, and remediation recommendations
- Timeline of service installation events with binary path analysis

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
