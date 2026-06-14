---
name: cb-hunting-for-data-staging-before-exfiltration
skill_id: cb-hunting-for-data-staging-before-exfiltration
journal_id: CB-SKL-231
description: Cold-box analyst playbook — Hunting For Data Staging Before Exfiltration.
  Detect data staging activity before exfiltration by monitoring for archive creation
  with 7-Zip/RAR, unusual temp folder access, large file consolidation, and staging
  directory patterns via EDR and process telemetry
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
- data-staging
- exfiltration
- t1074
- archive-detection
- edr
- threat-hunting
- dlp
cold_box_version: 2
inspired_by: hunting-for-data-staging-before-exfiltration
---

# Hunting For Data Staging Before Exfiltration (cold-box)

> **Journal ID:** `CB-SKL-231` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-231`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-data-staging-before-exfiltration")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-data-staging-before-exfiltration")` → note **`CB-SKL-231`**
2. `log_skill(case_id, journal_id="CB-SKL-231", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-231` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for data staging before exfiltration
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |
| `tar` | `SIFT-003` | yes | yes |
| `7z` | `SIFT-046` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-231] file per playbook step",
  "why": "Executing cb-hunting-for-data-staging-before-exfiltration \u2014 see Procedure section",
  "extra_args": []
}
```

### `zip` → `SIFT-036`

```json
{
  "tool_id": "SIFT-036",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-231] zip per playbook step",
  "why": "Executing cb-hunting-for-data-staging-before-exfiltration \u2014 see Procedure section",
  "extra_args": []
}
```

### `tar` → `SIFT-003`

```json
{
  "tool_id": "SIFT-003",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-231] tar per playbook step",
  "why": "Executing cb-hunting-for-data-staging-before-exfiltration \u2014 see Procedure section",
  "extra_args": []
}
```

### `7z` → `SIFT-046`

```json
{
  "tool_id": "SIFT-046",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-231] 7z per playbook step",
  "why": "Executing cb-hunting-for-data-staging-before-exfiltration \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-231` (`cb-hunting-for-data-staging-before-exfiltration`)

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

Before exfiltrating data, adversaries typically stage collected files in a central location (MITRE ATT&CK T1074). This involves creating archives with tools like 7-Zip, RAR, or tar, consolidating files from multiple directories, and using temporary or hidden staging directories. This skill detects staging behavior by analyzing process creation logs for archiver activity, monitoring file system events in common staging paths, and identifying anomalous file consolidation patterns.


## When to Use

- When investigating security incidents that require hunting for data staging before exfiltration
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- EDR or Sysmon telemetry with process creation and file system events
- Windows Event Logs (Event ID 4688) or Sysmon Event ID 1, 11
- Python 3.8+ with standard library
- Access to process creation logs in JSON/CSV format

## Steps

1. **Detect Archive Tool Execution** — Monitor for 7z.exe, rar.exe, tar, zip, and WinRAR process creation with compression arguments
2. **Identify Staging Directories** — Flag file writes to common staging locations (Recycle Bin, %TEMP%, ProgramData, hidden directories)
3. **Detect Large File Consolidation** — Identify patterns of multiple file reads followed by writes to a single directory
4. **Monitor Sensitive Path Access** — Track bulk reads from document directories, database paths, and network shares
5. **Analyze Archive Metadata** — Extract and analyze archive file sizes, creation times, and source paths
6. **Score Staging Risk** — Apply heuristic scoring based on archive size, source diversity, staging path suspicion, and timing
7. **Generate Hunt Report** — Produce a structured report with staging event timeline and MITRE ATT&CK mapping

## Expected Output

- JSON report of detected staging events with risk scores
- Archive creation timeline with source file analysis
- MITRE ATT&CK mapping (T1074.001, T1074.002, T1560)
- Staging directory heat map showing suspicious write activity

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
