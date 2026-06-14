---
name: cb-hunting-for-registry-run-key-persistence
skill_id: cb-hunting-for-registry-run-key-persistence
journal_id: CB-SKL-054
description: Cold-box analyst playbook — Hunting For Registry Run Key Persistence.
  Detect MITRE ATT&CK T1547.001 registry Run key persistence by analyzing Sysmon Event
  ID 13 logs and registry queries to identify malicious auto-start entries.
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- windows
host_platforms:
- linux
tags:
- persistence
- registry-run-keys
- t1547-001
- sysmon
- threat-hunting
- windows-forensics
- mitre-attack
cold_box_version: 2
inspired_by: hunting-for-registry-run-key-persistence
---

# Hunting For Registry Run Key Persistence (cold-box)

> **Journal ID:** `CB-SKL-054` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-054`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-registry-run-key-persistence")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-registry-run-key-persistence")` → note **`CB-SKL-054`**
2. `log_skill(case_id, journal_id="CB-SKL-054", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-054` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for registry run key persistence
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `regsvr32` | `SIFT-100` | no | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-054] powershell per playbook step",
  "why": "Executing cb-hunting-for-registry-run-key-persistence \u2014 see Procedure section",
  "extra_args": []
}
```

### `regsvr32` → `SIFT-100`

```json
{
  "tool_id": "SIFT-100",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-054] regsvr32 per playbook step",
  "why": "Executing cb-hunting-for-registry-run-key-persistence \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-054` (`cb-hunting-for-registry-run-key-persistence`)

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

Registry Run keys (T1547.001) are one of the most commonly used persistence mechanisms by adversaries. When a program is added to a Run key in the Windows registry, it executes automatically when a user logs in. Attackers abuse keys under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, and their RunOnce counterparts to maintain persistence. Sysmon Event ID 13 (RegistryEvent - Value Set) captures registry value modifications including the target object path, the process that made the change, and the new value. Detection involves monitoring these events for suspicious executables in temp directories, encoded PowerShell commands, LOLBin paths, and processes that do not normally create Run key entries. Chaining Event 13 with Event 1 (Process Creation) and Event 11 (FileCreate) strengthens detection by confirming payload creation and execution.


## When to Use

- When investigating security incidents that require hunting for registry run key persistence
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Windows systems with Sysmon installed and configured to log Event ID 13
- Sysmon config with RegistryEvent rules for Run/RunOnce keys
- Python 3.9+ with `json`, `xml.etree.ElementTree`, `re` modules
- SIEM or log aggregator collecting Sysmon logs (Splunk, Elastic, Sentinel)
- Knowledge of legitimate auto-start programs for baseline comparison

## Steps

1. Collect Sysmon Event ID 13 logs filtered for Run/RunOnce key paths
2. Parse event XML/JSON for TargetObject, Details (value written), Image (modifying process)
3. Flag entries where the value points to temp directories, AppData, or ProgramData
4. Detect encoded PowerShell commands or script interpreters in registry values
5. Identify LOLBin abuse (mshta.exe, rundll32.exe, regsvr32.exe, wscript.exe)
6. Compare against known-good baseline of legitimate auto-start entries
7. Check if the modifying process (Image) is unusual (cmd.exe, powershell.exe, python.exe)
8. Chain with Event ID 1 to verify if the registered binary was recently created
9. Generate detection report with MITRE ATT&CK mapping and severity scores
10. Produce Sigma/Splunk detection rules from findings

## Expected Output

A JSON report listing suspicious Run key entries with the registry path, value written, modifying process, timestamp, MITRE technique mapping, severity rating, and recommended Sigma detection rules.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
