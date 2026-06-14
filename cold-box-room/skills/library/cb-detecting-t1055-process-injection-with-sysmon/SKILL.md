---
name: cb-detecting-t1055-process-injection-with-sysmon
skill_id: cb-detecting-t1055-process-injection-with-sysmon
journal_id: CB-SKL-032
description: Cold-box analyst playbook — Detecting T1055 Process Injection With Sysmon.
  Detect process injection techniques (T1055) including classic DLL injection, process
  hollowing, and APC injection by analyzing Sysmon events for cross-process memory
  operations, remote thread creation, and anomalous DLL loading patterns.
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- memory
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- process-injection
- sysmon
- mitre-t1055
- defense-evasion
- dll-injection
- process-hollowing
cold_box_version: 2
inspired_by: detecting-t1055-process-injection-with-sysmon
---

# Detecting T1055 Process Injection With Sysmon (cold-box)

> **Journal ID:** `CB-SKL-032` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-032`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-t1055-process-injection-with-sysmon")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-t1055-process-injection-with-sysmon")` → note **`CB-SKL-032`**
2. `log_skill(case_id, journal_id="CB-SKL-032", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-032` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for defense evasion techniques that hide malicious code inside legitimate processes
- After EDR alerts for suspicious cross-process memory access or remote thread creation
- When investigating malware that injects into svchost.exe, explorer.exe, or other system processes
- During purple team exercises testing detection of process injection variants
- When validating Sysmon configuration coverage for injection detection

## Tool map (SIFT via MCP)

**Execution mode:** `partial` — Tools mapped but some are unavailable — check `describe_sift_tool` / `list_sift_tools`.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `handle` | `SIFT-178` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-032] handle per playbook step",
  "why": "Executing cb-detecting-t1055-process-injection-with-sysmon \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-032` (`cb-detecting-t1055-process-injection-with-sysmon`)

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

- When hunting for defense evasion techniques that hide malicious code inside legitimate processes
- After EDR alerts for suspicious cross-process memory access or remote thread creation
- When investigating malware that injects into svchost.exe, explorer.exe, or other system processes
- During purple team exercises testing detection of process injection variants
- When validating Sysmon configuration coverage for injection detection

## Prerequisites

- Sysmon deployed with comprehensive configuration capturing Events 1, 7, 8, 10, 25
- Event ID 8 (CreateRemoteThread) enabled for remote thread detection
- Event ID 10 (ProcessAccess) configured with appropriate access mask filters
- Event ID 7 (ImageLoaded) for DLL injection detection
- Event ID 25 (ProcessTampering) for process hollowing on Sysmon 13+
- SIEM platform for correlation and alerting

## Workflow

1. **Monitor CreateRemoteThread (Event 8)**: Detect when one process creates a thread in another process's address space. This is the primary indicator of classic DLL injection and shellcode injection.
2. **Analyze ProcessAccess (Event 10)**: Track cross-process handle requests with PROCESS_VM_WRITE (0x0020), PROCESS_VM_OPERATION (0x0008), and PROCESS_CREATE_THREAD (0x0002) access rights. Legitimate processes rarely need these on other processes.
3. **Detect Anomalous DLL Loading (Event 7)**: Identify DLLs loaded from unusual paths (user temp directories, download folders) into system processes.
4. **Hunt Process Hollowing (Event 25)**: Sysmon 13+ generates ProcessTampering events when the executable image in memory diverges from what was mapped from disk -- a hallmark of process hollowing (T1055.012).
5. **Correlate with Process Creation**: Link injection events to the originating process creation (Event 1) to build the full attack chain from initial execution to injection.
6. **Filter Known-Good Cross-Process Activity**: Exclude legitimate software that performs cross-process operations (debuggers, AV products, accessibility tools, RMM agents).
7. **Map to ATT&CK Sub-Techniques**: Classify detected injection as classic injection (T1055.001), PE injection (T1055.002), thread execution hijacking (T1055.003), APC injection (T1055.004), thread local storage (T1055.005), process hollowing (T1055.012), or process doppelganging (T1055.013).

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1055.001 | Dynamic-link Library Injection |
| T1055.002 | Portable Executable Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.004 | Asynchronous Procedure Call (APC) Injection |
| T1055.005 | Thread Local Storage |
| T1055.012 | Process Hollowing |
| T1055.013 | Process Doppelganging |
| T1055.015 | ListPlanting |
| Sysmon Event 8 | CreateRemoteThread detected |
| Sysmon Event 10 | ProcessAccess with memory write permissions |
| Sysmon Event 25 | ProcessTampering (image mismatch) |
| Access Mask 0x1FFFFF | PROCESS_ALL_ACCESS -- full cross-process control |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Primary telemetry source for injection detection |
| Process Hacker | Manual investigation of process memory regions |
| PE-sieve | Scan running processes for hollowed/injected code |
| Moneta | Detect anomalous memory regions in processes |
| Splunk / Elastic | SIEM correlation of Sysmon events |
| Volatility | Memory forensics for injection artifacts |
| Hollows Hunter | Automated scan for hollowed processes |

## Detection Queries

### Splunk -- Remote Thread Creation
```spl
index=sysmon EventCode=8
| where SourceImage!=TargetImage
| where NOT match(SourceImage, "(?i)(csrss|lsass|services|svchost|MsMpEng|SecurityHealthService|vmtoolsd)\.exe$")
| eval suspicious=if(match(TargetImage, "(?i)(svchost|explorer|lsass|winlogon|csrss|services)\.exe$"), "high_value_target", "normal_target")
| where suspicious="high_value_target"
| table _time Computer SourceImage SourceProcessId TargetImage TargetProcessId StartFunction NewThreadId
```

### Splunk -- Suspicious ProcessAccess Patterns
```spl
index=sysmon EventCode=10
| where SourceImage!=TargetImage
| where match(GrantedAccess, "(0x1FFFFF|0x1F3FFF|0x143A|0x0040)")
| where match(TargetImage, "(?i)(lsass|svchost|explorer|winlogon)\.exe$")
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|svchost|taskmgr|procexp)\.exe$")
| table _time Computer SourceImage TargetImage GrantedAccess CallTrace
```

### KQL -- Process Injection via Remote Thread
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessFileName !in~ ("csrss.exe", "lsass.exe", "services.exe", "svchost.exe")
| where FileName in~ ("svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, ProcessCommandLine
```

### Sigma Rule -- Process Injection Detection
```yaml
title: Process Injection via CreateRemoteThread into System Process
status: stable
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        TargetImage|endswith:
            - '\svchost.exe'
            - '\explorer.exe'
            - '\lsass.exe'
            - '\winlogon.exe'
    filter_legitimate:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\lsass.exe'
            - '\services.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter_legitimate
level: high
tags:
    - attack.defense_evasion
    - attack.t1055
```

## Common Scenarios

1. **Classic DLL Injection**: Malware uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread to load a malicious DLL into a target process. Detected via Sysmon Event 8.
2. **Process Hollowing (RunPE)**: Attacker creates a suspended process, unmaps its image, writes malicious PE, and resumes execution. Detected via Sysmon Event 25.
3. **APC Injection**: Malware queues an Asynchronous Procedure Call to threads of a target process using QueueUserAPC. Harder to detect, requires Event 10 monitoring.
4. **Reflective DLL Injection**: DLL is loaded directly from memory without touching disk, bypassing ImageLoaded detection. Requires memory-level analysis.
5. **Process Doppelganging**: Leverages NTFS transactions to replace a legitimate process image. Detected via process integrity checking.

## Output Format

```
Hunt ID: TH-INJECT-[DATE]-[SEQ]
Host: [Hostname]
Source Process: [Injecting process path]
Source PID: [Process ID]
Target Process: [Target process path]
Target PID: [Process ID]
Injection Type: [DLL/Shellcode/Hollowing/APC]
Sysmon Events: [Event IDs triggered]
Access Mask: [Granted access value]
Risk Level: [Critical/High/Medium/Low]
ATT&CK Sub-Technique: [T1055.xxx]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
