---
name: cb-detecting-fileless-attacks-on-endpoints
skill_id: cb-detecting-fileless-attacks-on-endpoints
journal_id: CB-SKL-187
description: Cold-box analyst playbook — Detecting Fileless Attacks On Endpoints.
  Detects fileless malware and in-memory attacks that execute entirely in RAM without
  writing persistent files to disk, evading traditional antivirus. Use when building
  detections for PowerShell-based attacks, reflective DLL injection, WMI pe
domain: cold-box
subdomain: endpoint-security
tier: adjacent
case_profiles:
- memory
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- endpoint
- fileless-malware
- memory-attacks
- PowerShell
- detection-engineering
cold_box_version: 2
inspired_by: detecting-fileless-attacks-on-endpoints
---

# Detecting Fileless Attacks On Endpoints (cold-box)

> **Journal ID:** `CB-SKL-187` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-187`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-fileless-attacks-on-endpoints")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-fileless-attacks-on-endpoints")` → note **`CB-SKL-187`**
2. `log_skill(case_id, journal_id="CB-SKL-187", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-187` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Building detection rules for fileless malware that operates entirely in memory
- Hunting for PowerShell-based attacks, reflective DLL injection, and WMI abuse
- Configuring endpoint telemetry (Sysmon, AMSI, PowerShell logging) to capture fileless indicators
- Investigating incidents where traditional AV found no malicious files

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-187] powershell per playbook step",
  "why": "Executing cb-detecting-fileless-attacks-on-endpoints \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-187] file per playbook step",
  "why": "Executing cb-detecting-fileless-attacks-on-endpoints \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-187` (`cb-detecting-fileless-attacks-on-endpoints`)

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

## When to Use

Use this skill when:
- Building detection rules for fileless malware that operates entirely in memory
- Hunting for PowerShell-based attacks, reflective DLL injection, and WMI abuse
- Configuring endpoint telemetry (Sysmon, AMSI, PowerShell logging) to capture fileless indicators
- Investigating incidents where traditional AV found no malicious files

**Do not use** for detecting file-based malware or for malware reverse engineering.

## Prerequisites

- Sysmon with process creation and WMI event logging enabled
- PowerShell Script Block Logging and Module Logging enabled
- AMSI (Antimalware Scan Interface) enabled for script content inspection
- EDR with behavioral detection capabilities (MDE, CrowdStrike, SentinelOne)

## Workflow

### Step 1: Enable Required Telemetry

```powershell
# Enable PowerShell Script Block Logging (GPO or registry)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name EnableScriptBlockLogging -Value 1 -PropertyType DWORD -Force

# Enable PowerShell Module Logging
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name EnableModuleLogging -Value 1 -PropertyType DWORD -Force

# Enable PowerShell Transcription
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name EnableTranscripting -Value 1 -PropertyType DWORD -Force

# Sysmon config for fileless detection (key events):
# Event ID 1: Process creation (captures CommandLine)
# Event ID 7: Image loaded (DLL loading)
# Event ID 8: CreateRemoteThread (injection)
# Event ID 10: Process access (LSASS access)
# Event ID 19/20/21: WMI events
```

### Step 2: Detect PowerShell-Based Attacks

```
# Indicators of malicious PowerShell:

# Encoded command execution
EventID: 1
CommandLine contains: "powershell" AND ("-enc" OR "-e " OR "-encodedcommand" OR "FromBase64String")

# Download cradle patterns
CommandLine contains: "IEX" AND ("Net.WebClient" OR "DownloadString" OR "Invoke-WebRequest")
CommandLine contains: "Invoke-Expression" AND "New-Object"

# AMSI bypass attempts (Event ID 4104 - Script Block)
ScriptBlock contains: ("Amsi"+"Utils") OR ("amsi"+"InitFailed") OR "SetValue.*amsi"

# Splunk query for suspicious PowerShell:
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(iex|invoke-expression|downloadstring|net\.webclient|frombase64|bypass|amsi.utils)")
| table _time host ScriptBlockText
```

### Step 3: Detect Process Injection Techniques

```
# Reflective DLL injection - loads DLL from memory without touching disk
# Detection: Sysmon Event 7 (ImageLoaded) where image path is unusual
EventID: 7
ImageLoaded NOT starts with: "C:\Windows\" AND NOT starts with: "C:\Program Files"

# Process hollowing - creates process in suspended state, replaces memory
# Detection: Process creation followed by immediate memory write
EventID: 1 + 10 correlation
# Process created then accessed with PROCESS_VM_WRITE

# APC injection - queues code to thread's async procedure call queue
# Detection: Sysmon CreateRemoteThread from non-system process
EventID: 8
SourceImage NOT IN (known_legitimate_sources)

# MDE KQL:
DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall", "NtAllocateVirtualMemoryApiCall")
| where InitiatingProcessFileName !in ("MsMpEng.exe", "svchost.exe")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FileName
```

### Step 4: Detect WMI-Based Persistence

```
# Sysmon Event IDs 19/20/21 for WMI events
EventID: 19  # WmiEventFilter activity detected
EventID: 20  # WmiEventConsumer activity detected
EventID: 21  # WmiEventConsumerToFilter activity detected

# Any WMI event subscription creation is suspicious unless expected
# Common malicious WMI persistence:
Consumer contains: "CommandLineEventConsumer" OR "ActiveScriptEventConsumer"

# Query for WMI subscriptions via osquery or PowerShell:
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

### Step 5: Detect Registry-Based Execution

```
# Malware stored in registry values and executed via PowerShell
# Sysmon Event 13 - Registry value set with encoded content
EventID: 13
TargetObject contains: "CurrentVersion\Run"
Details: unusually long value or Base64-encoded content

# Detection query:
index=sysmon EventCode=13
| where match(Details, "[A-Za-z0-9+/=]{100,}")
| table _time host TargetObject Details Image
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Fileless Malware** | Malware that operates entirely in memory without writing executable files to disk |
| **AMSI** | Antimalware Scan Interface; Windows API allowing security products to inspect script content before execution |
| **Reflective DLL Injection** | Loading a DLL from memory rather than disk, avoiding file-based detection |
| **Process Hollowing** | Creating a legitimate process in suspended state and replacing its memory with malicious code |
| **Script Block Logging** | PowerShell logging feature that captures deobfuscated script content (Event ID 4104) |

## Tools & Systems

- **Sysmon**: Kernel-level process, DLL, and WMI monitoring
- **AMSI**: Windows script content inspection API
- **PowerShell Logging**: Script Block, Module, and Transcription logging
- **Microsoft Defender for Endpoint**: Behavioral detection for fileless techniques
- **Volatility 3**: Memory forensics for post-incident fileless malware analysis

## Common Pitfalls

- **Relying on file-based AV**: Traditional AV that scans files on disk will miss fileless attacks entirely. Behavioral detection and AMSI are required.
- **Disabled PowerShell logging**: Without Script Block Logging, deobfuscated PowerShell commands are invisible to defenders.
- **AMSI bypass not detected**: Sophisticated attackers bypass AMSI before executing payloads. Detect AMSI bypass attempts as a high-priority alert.
- **Not monitoring WMI events**: WMI persistence is a favored technique of APT groups. Sysmon events 19-21 must be enabled.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
