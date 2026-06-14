---
name: cb-windows-shellbag-artifacts
skill_id: cb-windows-shellbag-artifacts
journal_id: CB-SKL-123
description: Cold-box analyst playbook — Windows Shellbag Artifacts. Analyze Windows
  Shellbag registry artifacts to reconstruct folder browsing activity, detect access
  to removable media and network shares, and establish user interaction with directories
  even after deletion using SBECmd and ShellBags Explore
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- windows_usb
execution_mode: sift_runnable
artifact_platforms:
- windows
host_platforms:
- linux
tags:
- shellbags
- windows-registry
- sbecmd
- shellbags-explorer
- folder-access
- user-activity
- removable-media
- network-shares
- bagmru
- dfir
cold_box_version: 2
inspired_by: analyzing-windows-shellbag-artifacts
---

# Windows Shellbag Artifacts (cold-box)

> **Journal ID:** `CB-SKL-123` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-123`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-windows-shellbag-artifacts")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-windows-shellbag-artifacts")` → note **`CB-SKL-123`**
2. `log_skill(case_id, journal_id="CB-SKL-123", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-123` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing windows shellbag artifacts
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `mmls` | `SIFT-160` | no | yes |
| `img_stat` | `SIFT-154` | yes | yes |
| `powershell` | `SIFT-179` | no | no |
| `SBECmd` | `SIFT-226` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `mmls` → `SIFT-160`

```json
{
  "tool_id": "SIFT-160",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-123] mmls per playbook step",
  "why": "Executing cb-windows-shellbag-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-123] img_stat per playbook step",
  "why": "Executing cb-windows-shellbag-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-123] powershell per playbook step",
  "why": "Executing cb-windows-shellbag-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `SBECmd` → `SIFT-226`

```json
{
  "tool_id": "SIFT-226",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-123] SBECmd per playbook step",
  "why": "Executing cb-windows-shellbag-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-123] sort per playbook step",
  "why": "Executing cb-windows-shellbag-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-123] file per playbook step",
  "why": "Executing cb-windows-shellbag-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `zip` → `SIFT-036`

```json
{
  "tool_id": "SIFT-036",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-123] zip per playbook step",
  "why": "Executing cb-windows-shellbag-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-123` (`cb-windows-shellbag-artifacts`)

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

Shellbags are Windows registry artifacts that track how users interact with folders through Windows Explorer, storing view settings such as icon size, window position, sort order, and view mode. From a forensic perspective, Shellbags provide definitive evidence of folder access -- even folders that no longer exist on the system. When a user browses to a folder via Windows Explorer, the Open/Save dialog, or the Control Panel, a Shellbag entry is created or updated in the user's registry hive. These entries persist after folder deletion, drive disconnection, and even across user profile resets, making them invaluable for proving that a user navigated to specific directories on local drives, USB devices, network shares, or zip archives.


## When to Use

- When investigating security incidents that require analyzing windows shellbag artifacts
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with digital forensics concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Registry Locations

### Windows 7/8/10/11

| Hive | Key Path | Stores |
|------|---------|--------|
| NTUSER.DAT | Software\Microsoft\Windows\Shell\BagMRU | Folder hierarchy tree |
| NTUSER.DAT | Software\Microsoft\Windows\Shell\Bags | View settings per folder |
| UsrClass.dat | Local Settings\Software\Microsoft\Windows\Shell\BagMRU | Desktop/Explorer shell |
| UsrClass.dat | Local Settings\Software\Microsoft\Windows\Shell\Bags | Additional view settings |

### BagMRU Structure

The BagMRU key contains a hierarchical tree of numbered subkeys representing the directory structure. Each subkey value contains a Shell Item (SHITEMID) binary blob encoding the folder identity:

- **Root (BagMRU)**: Desktop namespace root
- **BagMRU\0**: Typically "My Computer"
- **BagMRU\0\0**: First drive (e.g., C:)
- **BagMRU\0\0\0**: First subfolder on C:

Each Shell Item contains:
- Item type (folder, drive, network, zip, control panel)
- Short name (8.3 format)
- Long name (Unicode)
- Creation/modification timestamps
- MFT entry/sequence for NTFS folders

## Analysis with EZ Tools

### SBECmd (Command Line)

```powershell
# Parse shellbags from a directory of registry hives
SBECmd.exe -d "C:\Evidence\Registry" --csv C:\Output --csvf shellbags.csv

# Parse from a live system (requires admin)
SBECmd.exe --live --csv C:\Output --csvf live_shellbags.csv

# Key output columns:
# AbsolutePath - Full reconstructed path
# CreatedOn - When the folder was first browsed
# ModifiedOn - When view settings were last changed
# AccessedOn - Last access timestamp
# ShellType - Type of shell item (Directory, Drive, Network, etc.)
# Value - Raw shell item data
```

### ShellBags Explorer (GUI)

```powershell
# Launch GUI tool for interactive analysis
ShellBagsExplorer.exe

# Load registry hives: File > Load Hive
# Navigate the tree structure to see folder hierarchy
# Right-click entries for detailed shell item properties
```

## Forensic Investigation Scenarios

### Proving USB Device Browsing

```text
Shellbag Path: My Computer\E:\Confidential\Project_Files
ShellType: Directory (on removable volume)
CreatedOn: 2025-03-15 09:30:00 UTC

This proves the user navigated to E:\Confidential\Project_Files
via Windows Explorer, even if the USB drive is no longer connected.
The volume letter E: and directory timestamps can be correlated
with USBSTOR and MountPoints2 registry entries.
```

### Detecting Network Share Access

```text
Shellbag Path: \\FileServer01\Finance\Q4_Reports
ShellType: Network Location
AccessedOn: 2025-02-20 14:15:00 UTC

This proves the user browsed to a network share, even if
the share has been decommissioned or access revoked.
```

### Identifying Deleted Folder Knowledge

```text
Shellbag Path: C:\Users\suspect\Documents\Exfiltration_Staging
ShellType: Directory
CreatedOn: 2025-01-10 08:00:00 UTC

Even though C:\Users\suspect\Documents\Exfiltration_Staging
no longer exists, the Shellbag entry proves the user
created and navigated to this folder.
```

## Limitations

- Shellbags only record folder-level interactions, not individual file access
- Only created through Windows Explorer shell and Open/Save dialogs
- Command-line access (cmd, PowerShell) does not generate Shellbag entries
- Programmatic file access via APIs does not generate Shellbag entries
- Timestamps may reflect view setting changes, not necessarily folder access
- Windows may batch-update Shellbag entries during Explorer shutdown

## References

- Shellbags Forensic Analysis 2025: https://www.cybertriage.com/blog/shellbags-forensic-analysis-2025/
- SANS Shellbag Forensics: https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags
- Magnet Forensics Shellbag Analysis: https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/
- ShellBags Explorer: https://ericzimmerman.github.io/

## Example Output

```text
$ SBECmd.exe -d "C:\Evidence\Users\jsmith" --csv /analysis/shellbag_output

SBECmd v2.1.0 - ShellBags Explorer (Command Line)
====================================================
Processing hives for user: jsmith
  NTUSER.DAT:  C:\Evidence\Users\jsmith\NTUSER.DAT
  UsrClass.dat: C:\Evidence\Users\jsmith\AppData\Local\Microsoft\Windows\UsrClass.dat

[+] NTUSER.DAT shellbag entries:   456
[+] UsrClass.dat shellbag entries: 1,234
[+] Total shellbag entries:        1,690

--- Folder Access Timeline (Incident Window) ---
Last Accessed (UTC)     | Folder Path                                             | Type        | Access Count
------------------------|---------------------------------------------------------|-------------|-------------
2024-01-15 14:34:05     | C:\Users\jsmith\Downloads                               | File System | 45
2024-01-15 14:36:25     | C:\ProgramData\Updates                                  | File System | 3
2024-01-15 15:05:00     | \\FILESERV01\Finance                                    | Network     | 2
2024-01-15 15:12:30     | \\FILESERV01\Finance\Q4_Reports                          | Network     | 1
2024-01-15 15:30:00     | E:\                                                     | Removable   | 4
2024-01-15 15:30:45     | E:\Backup                                               | Removable   | 3
2024-01-15 15:31:20     | E:\Backup\Corporate_Data                                | Removable   | 2
2024-01-15 16:12:45     | \\FILESERV01\HR\Employees                                | Network     | 1
2024-01-15 16:15:00     | \\FILESERV01\HR\Employees\Records_2024                   | Network     | 1
2024-01-16 02:35:00     | C:\Windows\Temp                                         | File System | 5
2024-01-17 02:44:00     | C:\ProgramData\svc                                     | File System | 2
2024-01-18 01:10:00     | C:\Users\jsmith\AppData\Local\Temp                      | File System | 8

--- Network Share Access ---
  \\FILESERV01\Finance             First: 2023-09-10  Last: 2024-01-15
  \\FILESERV01\Finance\Q4_Reports  First: 2024-01-15  Last: 2024-01-15  (NEW)
  \\FILESERV01\HR\Employees        First: 2024-01-15  Last: 2024-01-15  (NEW)
  \\DC01\SYSVOL                    First: 2023-03-15  Last: 2024-01-16  (anomalous access time)

--- Removable Device Access ---
  E:\ (USB Drive)
    Volume Name:    BACKUP_DRIVE
    First Accessed: 2024-01-15 15:30:00 UTC
    Last Accessed:  2024-01-15 15:45:22 UTC
    Folders Browsed: 3 (E:\, E:\Backup, E:\Backup\Corporate_Data)

--- Deleted/No Longer Existing Paths ---
  C:\ProgramData\Updates\                (folder deleted, shellbag persists)
  C:\ProgramData\svc\                    (folder deleted, shellbag persists)
  C:\Windows\Temp\tools\                 (folder deleted, shellbag persists)

Summary:
  Total unique folders accessed:  1,690
  Network shares accessed:        4 (2 newly accessed during incident)
  Removable media:                1 USB device (data staging suspected)
  Deleted folder evidence:        3 paths (anti-forensics indicator)
  CSV exported to:                /analysis/shellbag_output/
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
