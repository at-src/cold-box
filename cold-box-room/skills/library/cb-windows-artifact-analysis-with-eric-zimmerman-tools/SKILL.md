---
name: cb-windows-artifact-analysis-with-eric-zimmerman-tools
skill_id: cb-windows-artifact-analysis-with-eric-zimmerman-tools
journal_id: CB-SKL-118
description: Cold-box analyst playbook — Windows Artifact Analysis With Eric Zimmerman
  Tools. Perform comprehensive Windows forensic artifact analysis using Eric Zimmerman's
  open-source EZ Tools suite including KAPE, MFTECmd, PECmd, LECmd, JLECmd, and Timeline
  Explorer for parsing registry hives, prefetch files, event logs, and file
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- eric-zimmerman
- ez-tools
- kape
- mftecmd
- pecmd
- lecmd
- jlecmd
- registry-forensics
- windows-forensics
- timeline-explorer
- dfir
- artifact-analysis
cold_box_version: 2
inspired_by: performing-windows-artifact-analysis-with-eric-zimmerman-tools
---

# Windows Artifact Analysis With Eric Zimmerman Tools (cold-box)

> **Journal ID:** `CB-SKL-118` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-118`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-windows-artifact-analysis-with-eric-zimmerman-tools")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-windows-artifact-analysis-with-eric-zimmerman-tools")` → note **`CB-SKL-118`**
2. `log_skill(case_id, journal_id="CB-SKL-118", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-118` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing windows artifact analysis with eric zimmerman tools
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `mmls` | `SIFT-160` | no | yes |
| `img_stat` | `SIFT-154` | yes | yes |
| `powershell` | `SIFT-179` | no | no |
| `EvtxECmd` | `SIFT-204` | yes | yes |
| `MFTECmd` | `SIFT-217` | yes | yes |
| `JLECmd` | `SIFT-212` | yes | yes |
| `SBECmd` | `SIFT-226` | yes | yes |
| `RECmd` | `SIFT-224` | yes | yes |
| `LECmd` | `SIFT-213` | yes | yes |
| `PECmd` | `SIFT-221` | no | no |
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `mmls` → `SIFT-160`

```json
{
  "tool_id": "SIFT-160",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] mmls per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] img_stat per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] powershell per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

### `EvtxECmd` → `SIFT-204`

```json
{
  "tool_id": "SIFT-204",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] EvtxECmd per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

### `MFTECmd` → `SIFT-217`

```json
{
  "tool_id": "SIFT-217",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] MFTECmd per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

### `JLECmd` → `SIFT-212`

```json
{
  "tool_id": "SIFT-212",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] JLECmd per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

### `SBECmd` → `SIFT-226`

```json
{
  "tool_id": "SIFT-226",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] SBECmd per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

### `RECmd` → `SIFT-224`

```json
{
  "tool_id": "SIFT-224",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-118] RECmd per playbook step",
  "why": "Executing cb-windows-artifact-analysis-with-eric-zimmerman-tools \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-118` (`cb-windows-artifact-analysis-with-eric-zimmerman-tools`)

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

Eric Zimmerman's EZ Tools suite is a collection of open-source forensic utilities that have become the global standard for Windows digital forensics investigations. Originally developed by a former FBI agent and current SANS instructor, these tools parse and analyze critical Windows artifacts including the Master File Table ($MFT), registry hives, prefetch files, event logs, shortcut (LNK) files, and jump lists. The suite integrates with KAPE (Kroll Artifact Parser and Extractor) for automated artifact collection and processing, producing structured CSV output that can be ingested into Timeline Explorer for visual analysis. EZ Tools are widely used by law enforcement, corporate incident responders, and forensic consultants worldwide.


## When to Use

- When conducting security assessments that involve performing windows artifact analysis with eric zimmerman tools
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Windows 10/11 or Windows Server 2016+ analysis workstation
- .NET 6 Runtime installed (required for EZ Tools v2.x+)
- Administrative privileges on the analysis workstation
- Forensic disk image or triage collection from target system
- At least 8 GB RAM (16 GB recommended for large datasets)
- Familiarity with NTFS file system structures and Windows internals

## Tool Suite Components

### KAPE (Kroll Artifact Parser and Extractor)

KAPE is the primary orchestration tool that automates artifact collection (Targets) and processing (Modules). It uses configuration files (.tkape and .mkape) to define what artifacts to collect and which EZ Tools to run against them.

**Installation and Setup:**

```powershell
# Download KAPE from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
# Extract to C:\Tools\KAPE

# Update KAPE targets and modules
C:\Tools\KAPE\gkape.exe  # GUI version
C:\Tools\KAPE\kape.exe   # CLI version

# Sync latest EZ Tools binaries
C:\Tools\KAPE\Get-KAPEUpdate.ps1
```

**Running KAPE Collection and Processing:**

```powershell
# Collect artifacts from E: drive (mounted forensic image) and process with EZ Tools
kape.exe --tsource E: --tdest C:\Cases\Case001\Collection --target KapeTriage --mdest C:\Cases\Case001\Processed --module !EZParser

# Collect specific artifact categories
kape.exe --tsource E: --tdest C:\Cases\Case001\Collection --target FileSystem,RegistryHives,EventLogs --mdest C:\Cases\Case001\Processed --module MFTECmd,RECmd,EvtxECmd

# Live system triage collection (run as administrator)
kape.exe --tsource C: --tdest D:\LiveTriage\Collection --target KapeTriage --mdest D:\LiveTriage\Processed --module !EZParser --vhdx LiveTriageImage
```

### MFTECmd - Master File Table Parser

MFTECmd parses the NTFS $MFT, $J (USN Journal), $Boot, $SDS, and $LogFile into human-readable CSV format.

```powershell
# Parse the $MFT file
MFTECmd.exe -f "C:\Cases\Evidence\$MFT" --csv C:\Cases\Output --csvf MFT_output.csv

# Parse the USN Journal ($J)
MFTECmd.exe -f "C:\Cases\Evidence\$J" --csv C:\Cases\Output --csvf USNJournal_output.csv

# Parse $Boot for volume information
MFTECmd.exe -f "C:\Cases\Evidence\$Boot" --csv C:\Cases\Output --csvf Boot_output.csv

# Parse $SDS for security descriptors
MFTECmd.exe -f "C:\Cases\Evidence\$SDS" --csv C:\Cases\Output --csvf SDS_output.csv
```

**Key Fields in MFT Output:**

| Field | Description |
|-------|-------------|
| EntryNumber | MFT record number |
| ParentEntryNumber | Parent directory MFT record |
| InUse | Whether the record is active or deleted |
| FileName | Name of the file or directory |
| Created0x10 | $STANDARD_INFORMATION creation timestamp |
| Created0x30 | $FILE_NAME creation timestamp |
| LastModified0x10 | $STANDARD_INFORMATION modification timestamp |
| IsDirectory | Boolean indicating directory or file |
| FileSize | Logical file size in bytes |
| Extension | File extension |

### PECmd - Prefetch File Parser

PECmd parses Windows Prefetch files (.pf) to provide evidence of program execution, including run counts and timestamps.

```powershell
# Parse all prefetch files from a directory
PECmd.exe -d "C:\Cases\Evidence\Windows\Prefetch" --csv C:\Cases\Output --csvf Prefetch_output.csv

# Parse a single prefetch file with verbose output
PECmd.exe -f "C:\Cases\Evidence\Windows\Prefetch\CMD.EXE-4A81B364.pf" --json C:\Cases\Output

# Parse prefetch with keyword filtering
PECmd.exe -d "C:\Cases\Evidence\Windows\Prefetch" -k "powershell,cmd,wscript,cscript,mshta" --csv C:\Cases\Output --csvf SuspiciousExec.csv
```

### RECmd - Registry Explorer Command Line

RECmd processes Windows registry hives using batch files that define which keys and values to extract.

```powershell
# Process all registry hives with the default batch file
RECmd.exe --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb -d "C:\Cases\Evidence\Registry" --csv C:\Cases\Output --csvf Registry_output.csv

# Process a single NTUSER.DAT hive
RECmd.exe -f "C:\Cases\Evidence\Users\suspect\NTUSER.DAT" --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb --csv C:\Cases\Output

# Process SYSTEM hive for USB device history
RECmd.exe -f "C:\Cases\Evidence\Registry\SYSTEM" --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb --csv C:\Cases\Output
```

### EvtxECmd - Windows Event Log Parser

EvtxECmd parses Windows Event Log (.evtx) files into structured CSV format with customizable event ID maps.

```powershell
# Parse all event logs from a directory
EvtxECmd.exe -d "C:\Cases\Evidence\Windows\System32\winevt\Logs" --csv C:\Cases\Output --csvf EventLogs_output.csv

# Parse a single event log
EvtxECmd.exe -f "C:\Cases\Evidence\Security.evtx" --csv C:\Cases\Output --csvf Security_output.csv

# Parse with custom maps for enhanced field extraction
EvtxECmd.exe -d "C:\Cases\Evidence\Logs" --csv C:\Cases\Output --maps C:\Tools\KAPE\Modules\bin\EvtxECmd\Maps
```

### LECmd and JLECmd - Shortcut and Jump List Parsers

```powershell
# Parse LNK files from Recent directory
LECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Cases\Output --csvf LNK_output.csv

# Parse Jump Lists (automatic destinations)
JLECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\Cases\Output --csvf JumpLists_auto.csv

# Parse Jump Lists (custom destinations)
JLECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" --csv C:\Cases\Output --csvf JumpLists_custom.csv
```

### SBECmd - Shellbag Explorer Command Line

```powershell
# Parse shellbags from a directory of registry hives
SBECmd.exe -d "C:\Cases\Evidence\Registry" --csv C:\Cases\Output --csvf Shellbags_output.csv

# Parse shellbags from a live system (requires admin)
SBECmd.exe --live --csv C:\Cases\Output --csvf LiveShellbags_output.csv
```

### Timeline Explorer - Visual Analysis

Timeline Explorer is the GUI tool for analyzing CSV output from all EZ Tools. It supports filtering, sorting, column grouping, and conditional formatting.

```powershell
# Launch Timeline Explorer and open CSV output
TimelineExplorer.exe "C:\Cases\Output\MFT_output.csv"
```

**Key Timeline Explorer Features:**
- Column-level filtering with regular expressions
- Conditional formatting for timestamp anomalies
- Multi-column sorting for chronological analysis
- Export filtered results to new CSV files
- Bookmarking rows of interest

## Investigation Workflow

### Step 1: Artifact Collection with KAPE

```powershell
# Full triage collection from forensic image mounted at E:
kape.exe --tsource E: --tdest C:\Cases\Case001\Collected --target KapeTriage --vhdx TriageImage --zv false
```

### Step 2: Artifact Processing with EZ Tools

```powershell
# Process all collected artifacts
kape.exe --msource C:\Cases\Case001\Collected --mdest C:\Cases\Case001\Processed --module !EZParser
```

### Step 3: Timeline Analysis

1. Open processed CSV files in Timeline Explorer
2. Sort by timestamp columns to establish chronological order
3. Filter for specific file extensions, paths, or event IDs
4. Cross-reference MFT timestamps with event log entries
5. Identify timestomping by comparing $SI and $FN timestamps
6. Document findings with bookmarks and exported filtered views

### Step 4: Timestomping Detection

```powershell
# In Timeline Explorer, compare these columns:
# Created0x10 ($STANDARD_INFORMATION) vs Created0x30 ($FILE_NAME)
# If Created0x10 < Created0x30, timestomping is indicated
# $FILE_NAME timestamps are harder to manipulate than $STANDARD_INFORMATION
```

## Forensic Artifacts Reference

| Tool | Artifact | Location |
|------|----------|----------|
| MFTECmd | $MFT | Root of NTFS volume |
| MFTECmd | $J (USN Journal) | $Extend\$UsnJrnl:$J |
| PECmd | Prefetch files | C:\Windows\Prefetch\*.pf |
| RECmd | NTUSER.DAT | C:\Users\{user}\NTUSER.DAT |
| RECmd | SYSTEM hive | C:\Windows\System32\config\SYSTEM |
| RECmd | SAM hive | C:\Windows\System32\config\SAM |
| RECmd | SOFTWARE hive | C:\Windows\System32\config\SOFTWARE |
| EvtxECmd | Event logs | C:\Windows\System32\winevt\Logs\*.evtx |
| LECmd | LNK files | C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\ |
| JLECmd | Jump lists | C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ |
| SBECmd | Shellbags | NTUSER.DAT and UsrClass.dat registry hives |

## Common Investigation Scenarios

### Malware Execution Evidence
1. Parse Prefetch with PECmd to identify executed binaries
2. Cross-reference with MFT for file creation timestamps
3. Check Amcache.hve with RECmd for SHA1 hashes of executables
4. Correlate with Event Log entries for process creation (Event ID 4688)

### Data Exfiltration Investigation
1. Parse USN Journal with MFTECmd for file rename/delete operations
2. Analyze LNK files with LECmd for recently accessed documents
3. Review Shellbags with SBECmd for directory browsing activity
4. Check for USB device connections in SYSTEM registry with RECmd

### Lateral Movement Detection
1. Parse Security.evtx with EvtxECmd for logon events (4624, 4625)
2. Analyze RDP-related event logs (Microsoft-Windows-TerminalServices)
3. Cross-reference with network share access from SMB logs
4. Review scheduled tasks and services for persistence mechanisms

## Output Format and Integration

All EZ Tools produce CSV output that can be:
- Analyzed in Timeline Explorer for visual investigation
- Imported into Splunk, Elastic, or other SIEM platforms
- Processed by Python/PowerShell scripts for automated analysis
- Combined into super timelines using log2timeline/Plaso

## References

- Eric Zimmerman's Tools: https://ericzimmerman.github.io/
- KAPE Documentation: https://ericzimmerman.github.io/KapeDocs/
- SANS EZ Tools Training: https://www.sans.org/tools/ez-tools
- SANS FOR508: Advanced Incident Response and Threat Hunting
- SANS FOR498: Battlefield Forensics & Data Acquisition

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
