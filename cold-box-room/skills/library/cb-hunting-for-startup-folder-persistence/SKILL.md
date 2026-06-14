---
name: cb-hunting-for-startup-folder-persistence
skill_id: cb-hunting-for-startup-folder-persistence
journal_id: CB-SKL-245
description: Cold-box analyst playbook — Hunting For Startup Folder Persistence. Detect
  T1547.001 startup folder persistence by monitoring Windows startup directories for
  suspicious file creation, analyzing autoruns entries, and using Python watchdog
  for real-time filesystem monitoring.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- T1547.001
- startup-folder
- persistence
- autoruns
- watchdog
- filesystem-monitoring
cold_box_version: 2
inspired_by: hunting-for-startup-folder-persistence
---

# Hunting For Startup Folder Persistence (cold-box)

> **Journal ID:** `CB-SKL-245` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-245`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-startup-folder-persistence")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-startup-folder-persistence")` → note **`CB-SKL-245`**
2. `log_skill(case_id, journal_id="CB-SKL-245", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-245` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for startup folder persistence
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `autoruns` | `SIFT-176` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `autoruns` → `SIFT-176`

```json
{
  "tool_id": "SIFT-176",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-245] autoruns per playbook step",
  "why": "Executing cb-hunting-for-startup-folder-persistence \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-245] file per playbook step",
  "why": "Executing cb-hunting-for-startup-folder-persistence \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-245` (`cb-hunting-for-startup-folder-persistence`)

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

Attackers use Windows startup folders for persistence (MITRE ATT&CK T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder). Files placed in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` execute automatically at user logon. This skill scans startup directories for suspicious files, monitors for real-time changes using Python watchdog, and analyzes file metadata to detect persistence implants.


## When to Use

- When investigating security incidents that require hunting for startup folder persistence
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `watchdog`, `pefile` (optional for PE analysis)
- Access to Windows startup folders (user and all-users)
- Windows Event Logs for Event ID 4663 correlation (optional)

## Steps

1. Enumerate all files in user and system startup directories
2. Analyze file types, creation timestamps, and digital signatures
3. Flag suspicious file extensions (.bat, .vbs, .ps1, .lnk, .exe)
4. Check for recently created files (< 7 days) as potential implants
5. Monitor startup folders in real-time using watchdog FileSystemEventHandler
6. Correlate with known legitimate startup entries
7. Generate threat hunting report with T1547.001 MITRE mapping

## Expected Output

- JSON report listing all startup folder contents with risk scores, file metadata, and suspicious indicators
- Real-time monitoring alerts for new file creation in startup directories

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
