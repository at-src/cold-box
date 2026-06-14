---
name: cb-detecting-evasion-techniques-in-endpoint-logs
skill_id: cb-detecting-evasion-techniques-in-endpoint-logs
journal_id: CB-SKL-185
description: Cold-box analyst playbook — Detecting Evasion Techniques In Endpoint
  Logs. Detects defense evasion techniques used by adversaries in endpoint logs including
  log tampering, timestomping, process injection, and security tool disabling. Use
  when investigating suspicious endpoint behavior, building detection rules for
domain: cold-box
subdomain: endpoint-security
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- endpoint
- edr
- threat-hunting
- defense-evasion
- MITRE-ATT&CK
- detection-engineering
cold_box_version: 2
inspired_by: detecting-evasion-techniques-in-endpoint-logs
---

# Detecting Evasion Techniques In Endpoint Logs (cold-box)

> **Journal ID:** `CB-SKL-185` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-185`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-evasion-techniques-in-endpoint-logs")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-evasion-techniques-in-endpoint-logs")` → note **`CB-SKL-185`**
2. `log_skill(case_id, journal_id="CB-SKL-185", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-185` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Hunting for adversary defense evasion techniques (MITRE ATT&CK TA0005) in endpoint telemetry
- Building detection rules for common evasion methods (process injection, timestomping, log clearing)
- Investigating incidents where adversaries disabled or bypassed security tools
- Analyzing endpoint logs for indicators of living-off-the-land binary (LOLBin) abuse

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `wevtutil` | `SIFT-185` | no | no |
| `regsvr32` | `SIFT-100` | no | yes |
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-185] powershell per playbook step",
  "why": "Executing cb-detecting-evasion-techniques-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `wevtutil` → `SIFT-185`

```json
{
  "tool_id": "SIFT-185",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-185] wevtutil per playbook step",
  "why": "Executing cb-detecting-evasion-techniques-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `regsvr32` → `SIFT-100`

```json
{
  "tool_id": "SIFT-100",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-185] regsvr32 per playbook step",
  "why": "Executing cb-detecting-evasion-techniques-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-185] sort per playbook step",
  "why": "Executing cb-detecting-evasion-techniques-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-185] file per playbook step",
  "why": "Executing cb-detecting-evasion-techniques-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-185` (`cb-detecting-evasion-techniques-in-endpoint-logs`)

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
- Hunting for adversary defense evasion techniques (MITRE ATT&CK TA0005) in endpoint telemetry
- Building detection rules for common evasion methods (process injection, timestomping, log clearing)
- Investigating incidents where adversaries disabled or bypassed security tools
- Analyzing endpoint logs for indicators of living-off-the-land binary (LOLBin) abuse

**Do not use** this skill for network-level evasion (use network traffic analysis) or for malware reverse engineering.

## Prerequisites

- Sysmon installed and configured with comprehensive logging rules (SwiftOnSecurity or Olaf Hartong config)
- Windows Security Event Log with advanced audit policy enabled
- EDR telemetry (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint)
- SIEM platform for log correlation (Splunk, Elastic, Sentinel)
- MITRE ATT&CK Enterprise matrix for technique reference

## Workflow

### Step 1: Detect Log Tampering (T1070)

**Windows Event Log clearing (T1070.001)**:
```
# Sysmon Event ID 1 (Process Create) for wevtutil
EventID: 1
CommandLine contains: "wevtutil cl" OR "wevtutil clear-log"

# Security Event ID 1102 - Audit log was cleared
EventID: 1102
Source: Microsoft-Windows-Eventlog

# System Event ID 104 - Event log was cleared
EventID: 104

# PowerShell log clearing
EventID: 1 (Sysmon)
CommandLine contains: "Clear-EventLog" OR "Remove-EventLog"

# Splunk query:
index=windows (EventCode=1102 OR EventCode=104)
  OR (EventCode=1 CommandLine="*wevtutil*cl*")
  OR (EventCode=1 CommandLine="*Clear-EventLog*")
| table _time host user CommandLine EventCode
```

**Timestomping (T1070.006)**:
```
# Sysmon Event ID 2 - File creation time changed
EventID: 2
# Look for creation times set far in the past on recently-written files
# Correlate with Event ID 11 (FileCreate) - if FileCreate is recent but
# creation time in Event ID 2 is old, timestomping is likely

# MDE Advanced Hunting (KQL):
DeviceFileEvents
| where ActionType == "FileTimestampModified"
| where Timestamp > ago(7d)
| extend TimeDiff = datetime_diff('day', Timestamp, ReportedFileCreationTime)
| where TimeDiff > 30
| project Timestamp, DeviceName, FileName, FolderPath,
    ReportedFileCreationTime, InitiatingProcessFileName
```

### Step 2: Detect Process Injection (T1055)

```
# Sysmon Event ID 8 - CreateRemoteThread
EventID: 8
# Alert when source process is unusual (not system processes)
# Filter out known legitimate: antivirus, debugging tools
SourceImage NOT IN ("C:\Windows\System32\csrss.exe",
                     "C:\Windows\System32\lsass.exe")

# Sysmon Event ID 10 - ProcessAccess with suspicious access masks
EventID: 10
GrantedAccess contains: "0x1F0FFF" OR "0x1FFFFF" OR "0x001F0FFF"
# PROCESS_ALL_ACCESS = 0x1F0FFF (common in injection)
# Filter legitimate: AV accessing all processes

# Sysmon Event ID 25 - Process Tampering
EventID: 25
Type: "Image is replaced"  # Process hollowing indicator

# Splunk detection:
index=sysmon EventCode=8
| where NOT match(SourceImage, "(?i)(csrss|svchost|MsMpEng|defender)")
| stats count by SourceImage TargetImage host
| where count < 5
| sort - count
```

### Step 3: Detect Security Tool Disabling (T1562)

```
# Service stopped events for security services
EventID: 7045 (new service) OR 7036 (service state change)
ServiceName IN ("WinDefend", "Sense", "CrowdStrike Falcon Sensor",
                 "SentinelAgent", "csagent", "MBAMService")

# Sysmon Event ID 1 - Processes that disable Defender
CommandLine contains: "Set-MpPreference -DisableRealtimeMonitoring"
  OR "sc stop WinDefend"
  OR "sc config WinDefend start= disabled"
  OR "net stop" AND ("windefend" OR "sense" OR "csagent")

# Registry modification to disable security features
# Sysmon Event ID 13 - Registry value set
TargetObject contains: "DisableAntiSpyware"
  OR "DisableRealtimeMonitoring"
  OR "DisableBehaviorMonitoring"
Details: "DWORD (0x00000001)"

# MDE KQL:
DeviceRegistryEvents
| where RegistryValueName in ("DisableAntiSpyware", "DisableRealtimeMonitoring")
| where RegistryValueData == "1"
| project Timestamp, DeviceName, RegistryKey, InitiatingProcessFileName
```

### Step 4: Detect Masquerading (T1036)

```
# Sysmon Event ID 1 - Process with legitimate name from unusual path
EventID: 1
Image contains: "svchost.exe" AND Image NOT starts with: "C:\Windows\System32\"
Image contains: "csrss.exe" AND Image NOT starts with: "C:\Windows\System32\"
Image contains: "lsass.exe" AND Image NOT starts with: "C:\Windows\System32\"

# Process name mismatch (original filename vs. current name)
# Sysmon captures OriginalFileName from PE header
EventID: 1
OriginalFileName != (parsed filename from Image path)

# Double extension files
EventID: 11 (FileCreate)
TargetFilename matches: "*\.pdf\.exe" OR "*\.doc\.exe" OR "*\.jpg\.exe"

# Splunk:
index=sysmon EventCode=1
| eval process_name=mvindex(split(Image,"\\"),-1)
| where (process_name="svchost.exe" AND NOT match(Image,"(?i)C:\\\\Windows\\\\System32"))
  OR (process_name="csrss.exe" AND NOT match(Image,"(?i)C:\\\\Windows\\\\System32"))
| table _time host Image ParentImage CommandLine User
```

### Step 5: Detect LOLBin Abuse (T1218, T1127)

```
# Common LOLBin abuse patterns:

# mshta.exe executing remote content
EventID: 1
Image ends with: "mshta.exe"
CommandLine contains: "http" OR "javascript:" OR "vbscript:"

# certutil.exe downloading files
EventID: 1
Image ends with: "certutil.exe"
CommandLine contains: "-urlcache" OR "-decode" OR "-encode"

# regsvr32.exe executing scriptlets
EventID: 1
Image ends with: "regsvr32.exe"
CommandLine contains: "/s /n /u /i:" OR "scrobj.dll"

# rundll32.exe with unusual DLLs
EventID: 1
Image ends with: "rundll32.exe"
CommandLine contains: "javascript:" OR ".js" OR "http:"

# MSBuild executing inline tasks
EventID: 1
Image contains: "MSBuild.exe"
CommandLine NOT contains: ".sln" AND NOT contains: ".csproj"
```

### Step 6: Build Detection Rule Correlation

```
# Combine multiple weak signals into high-confidence detection:

# Rule: Potential post-exploitation evasion chain
# Trigger when 3+ evasion techniques observed on same host within 1 hour

# Splunk correlation search:
index=sysmon host=*
| eval technique=case(
    EventCode=2, "timestomping",
    EventCode=8 AND NOT match(SourceImage,"csrss|svchost"), "process_injection",
    EventCode=1 AND match(CommandLine,"(?i)wevtutil.*cl"), "log_clearing",
    EventCode=13 AND match(TargetObject,"DisableRealtimeMonitoring"), "security_disable",
    EventCode=1 AND match(CommandLine,"(?i)(mshta|certutil.*urlcache|regsvr32.*/s.*/n)"), "lolbin_abuse",
    true(), NULL
)
| where isnotnull(technique)
| bin _time span=1h
| stats dc(technique) as technique_count values(technique) as techniques by host _time
| where technique_count >= 3
| sort - technique_count
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Defense Evasion (TA0005)** | MITRE ATT&CK tactic where adversaries attempt to avoid detection during operations |
| **Process Injection (T1055)** | Technique of injecting code into another process's memory space to execute in a trusted context |
| **Timestomping (T1070.006)** | Modifying file timestamps to make malicious files appear old and blend with legitimate files |
| **Masquerading (T1036)** | Naming malicious files or processes to match legitimate system files to avoid detection |
| **LOLBin** | Living Off the Land Binary; legitimate Windows tool repurposed by adversaries |
| **Indicator Removal (T1070)** | Clearing logs, deleting files, or modifying artifacts to remove evidence of compromise |

## Tools & Systems

- **Sysmon**: Advanced Windows system monitoring with kernel-level visibility
- **Microsoft Defender for Endpoint**: EDR with advanced hunting (KQL) for evasion detection
- **CrowdStrike Falcon**: IOA-based behavioral detection for evasion techniques
- **Elastic Security**: SIEM with prebuilt detection rules for ATT&CK evasion techniques
- **Sigma Rules**: Vendor-agnostic detection rule format with extensive evasion rule library

## Common Pitfalls

- **Alert fatigue from process injection rules**: Many legitimate tools (AV, accessibility) perform process injection. Maintain an allowlist of known-good source processes.
- **Missing Sysmon Event ID 8/10**: Default Sysmon configurations may not capture CreateRemoteThread or ProcessAccess. Use a comprehensive Sysmon config.
- **Ignoring parent process context**: A suspicious command line from cmd.exe is concerning only if the parent of cmd.exe is unusual (e.g., Excel spawning cmd.exe).
- **Not correlating across event types**: Single events are often benign. Combine multiple weak signals (process creation + network connection + file creation) for high-confidence detections.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
