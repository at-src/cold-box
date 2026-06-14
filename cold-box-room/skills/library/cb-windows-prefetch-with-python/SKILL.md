---
name: cb-windows-prefetch-with-python
skill_id: cb-windows-prefetch-with-python
journal_id: CB-SKL-121
description: Cold-box analyst playbook — Windows Prefetch With Python. Parse Windows
  Prefetch files using the windowsprefetch Python library to reconstruct application
  execution history, detect renamed or masquerading binaries, and identify suspicious
  program execution patterns.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- windows
host_platforms:
- linux
tags:
- digital-forensics
- windows
- prefetch
- execution-history
- incident-response
- malware-analysis
cold_box_version: 2
inspired_by: analyzing-windows-prefetch-with-python
---

# Windows Prefetch With Python (cold-box)

> **Journal ID:** `CB-SKL-121` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-121`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-windows-prefetch-with-python")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-windows-prefetch-with-python")` → note **`CB-SKL-121`**
2. `log_skill(case_id, journal_id="CB-SKL-121", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-121` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing windows prefetch with python
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `procdump64` | `SIFT-181` | no | no |
| `powershell` | `SIFT-179` | no | no |
| `wevtutil` | `SIFT-185` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `procdump64` → `SIFT-181`

```json
{
  "tool_id": "SIFT-181",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-121] procdump64 per playbook step",
  "why": "Executing cb-windows-prefetch-with-python \u2014 see Procedure section",
  "extra_args": []
}
```

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-121] powershell per playbook step",
  "why": "Executing cb-windows-prefetch-with-python \u2014 see Procedure section",
  "extra_args": []
}
```

### `wevtutil` → `SIFT-185`

```json
{
  "tool_id": "SIFT-185",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-121] wevtutil per playbook step",
  "why": "Executing cb-windows-prefetch-with-python \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-121] file per playbook step",
  "why": "Executing cb-windows-prefetch-with-python \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-121` (`cb-windows-prefetch-with-python`)

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

Windows Prefetch files (.pf) record application execution data including executable names, run counts, timestamps, loaded DLLs, and accessed directories. This skill covers parsing Prefetch files using the windowsprefetch Python library to reconstruct execution timelines, detect renamed or masquerading binaries by comparing executable names with loaded resources, and identifying suspicious programs that may indicate malware execution or lateral movement.


## When to Use

- When investigating security incidents that require analyzing windows prefetch with python
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `windowsprefetch` library (pip install windowsprefetch)
- Windows Prefetch files from C:\Windows\Prefetch\ (versions 17-30 supported)
- Understanding of Windows Prefetch file naming conventions (EXECUTABLE-HASH.pf)

## Steps

### Step 1: Collect Prefetch Files
Gather .pf files from target system's C:\Windows\Prefetch\ directory.

### Step 2: Parse Execution History
Extract executable name, run count, last execution timestamps, and volume information.

### Step 3: Detect Suspicious Execution
Flag known attack tools (mimikatz, psexec, etc.), renamed binaries, and unusual execution patterns.

### Step 4: Build Execution Timeline
Reconstruct chronological execution timeline from all Prefetch files.

## Expected Output

JSON report with execution history, suspicious executables, renamed binary indicators, and timeline reconstruction.

## Example Output

```text
$ python3 prefetch_analyzer.py --dir /evidence/Windows/Prefetch --output /analysis/prefetch_report

Windows Prefetch Analyzer v2.1
================================
Source: /evidence/Windows/Prefetch/
Prefetch Format: Windows 10 (MAM compressed, version 30)
Files Found: 234

--- Execution Timeline (Incident Window: 2024-01-15 to 2024-01-18) ---
Last Executed (UTC)     | Run Count | Filename                    | Hash     | Path
------------------------|-----------|-----------------------------|----------|------------------------------------------
2024-01-15 14:33:15     | 1         | Q4_REPORT.XLSM-2A1B3C4D.pf | 2A1B3C4D | C:\Users\jsmith\Downloads\Q4_Report.xlsm
2024-01-15 14:35:44     | 1         | POWERSHELL.EXE-A2B3C4D5.pf  | A2B3C4D5 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2024-01-15 14:36:30     | 3         | UPDATE_CLIENT.EXE-B3C4D5E6.pf| B3C4D5E6| C:\ProgramData\Updates\update_client.exe
2024-01-15 15:10:22     | 1         | NETSCAN.EXE-C4D5E6F7.pf     | C4D5E6F7 | C:\Users\jsmith\Downloads\netscan.exe
2024-01-16 02:28:00     | 1         | PROCDUMP64.EXE-D5E6F7A8.pf  | D5E6F7A8 | C:\Windows\Temp\procdump64.exe
2024-01-16 02:30:15     | 2         | MIMIKATZ.EXE-E6F7A8B9.pf    | E6F7A8B9 | C:\Windows\Temp\mimikatz.exe
2024-01-16 02:40:00     | 4         | PSEXEC.EXE-F7A8B9C0.pf      | F7A8B9C0 | C:\Users\jsmith\AppData\Local\Temp\psexec.exe
2024-01-17 02:45:00     | 1         | SDELETE64.EXE-A8B9C0D1.pf   | A8B9C0D1 | C:\Windows\Temp\sdelete64.exe
2024-01-18 03:00:45     | 1         | WEVTUTIL.EXE-B9C0D1E2.pf    | B9C0D1E2 | C:\Windows\System32\wevtutil.exe

--- Renamed Binary Detection ---
ALERT: UPDATE_CLIENT.EXE loaded DLLs consistent with Cobalt Strike beacon:
  Referenced DLLs: wininet.dll, ws2_32.dll, advapi32.dll, dnsapi.dll, netapi32.dll
  Volume: \VOLUME{01d94f2a3b5c7d8e-A4E73F21} (C:)
  Directories referenced:
    C:\ProgramData\Updates\
    C:\Windows\System32\

--- Execution Frequency Analysis ---
Most Executed (Top 5):
  1. SVCHOST.EXE          (267 runs)
  2. CHROME.EXE           (189 runs)
  3. EXPLORER.EXE         (156 runs)
  4. RUNTIMEBROKER.EXE    (134 runs)
  5. OUTLOOK.EXE          (98 runs)

First-Time Executions (Never seen before incident window):
  6 executables first run between 2024-01-15 and 2024-01-18

Summary:
  Total prefetch files:         234
  Suspicious executables:       6
  Renamed binary indicators:    1 (update_client.exe)
  Anti-forensics tools:         2 (sdelete64.exe, wevtutil.exe)
  JSON report: /analysis/prefetch_report/prefetch_timeline.json
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
