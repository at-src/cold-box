---
name: cb-hunting-for-persistence-via-wmi-subscriptions
skill_id: cb-hunting-for-persistence-via-wmi-subscriptions
journal_id: CB-SKL-240
description: Cold-box analyst playbook — Hunting For Persistence Via Wmi Subscriptions.
  Hunt for adversary persistence through Windows Management Instrumentation event
  subscriptions by monitoring WMI consumer, filter, and binding creation events that
  execute malicious code triggered by system events.
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
- wmi-persistence
- mitre-t1546-003
- event-subscription
- windows
- endpoint-detection
cold_box_version: 2
inspired_by: hunting-for-persistence-via-wmi-subscriptions
---

# Hunting For Persistence Via Wmi Subscriptions (cold-box)

> **Journal ID:** `CB-SKL-240` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-240`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-persistence-via-wmi-subscriptions")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-persistence-via-wmi-subscriptions")` → note **`CB-SKL-240`**
2. `log_skill(case_id, journal_id="CB-SKL-240", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-240` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When proactively searching for fileless persistence mechanisms in Windows environments
- After threat intelligence reports indicate WMI-based persistence by APT groups (APT29, APT32, FIN8)
- When investigating systems where malware persists across reboots despite cleanup attempts
- During incident response when standard persistence locations (Run keys, scheduled tasks) are clean
- When WmiPrvSe.exe is observed spawning unexpected child processes

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
  "purpose": "[CB-SKL-240] powershell per playbook step",
  "why": "Executing cb-hunting-for-persistence-via-wmi-subscriptions \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-240] file per playbook step",
  "why": "Executing cb-hunting-for-persistence-via-wmi-subscriptions \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-240` (`cb-hunting-for-persistence-via-wmi-subscriptions`)

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

- When proactively searching for fileless persistence mechanisms in Windows environments
- After threat intelligence reports indicate WMI-based persistence by APT groups (APT29, APT32, FIN8)
- When investigating systems where malware persists across reboots despite cleanup attempts
- During incident response when standard persistence locations (Run keys, scheduled tasks) are clean
- When WmiPrvSe.exe is observed spawning unexpected child processes

## Prerequisites

- Sysmon Event ID 19, 20, 21 (WMI Event Filter/Consumer/Binding) enabled
- Windows Event ID 5861 (WMI activity logging) from Microsoft-Windows-WMI-Activity
- PowerShell logging enabled (Script Block Logging, Module Logging)
- WMI repository access for enumeration
- SIEM platform for event correlation

## Workflow

1. **Enumerate Existing WMI Subscriptions**: Query all permanent WMI event subscriptions on target systems. A clean system typically has very few or zero permanent subscriptions, making anomalies easy to spot.
2. **Monitor WMI Event Creation (Sysmon 19/20/21)**: Sysmon Event 19 captures WmiEventFilter activity, Event 20 captures WmiEventConsumer activity, and Event 21 captures WmiEventConsumerToFilter binding.
3. **Analyze Consumer Types**: Focus on ActiveScriptEventConsumer (runs VBScript/JScript) and CommandLineEventConsumer (executes commands) -- these are the dangerous types used for persistence.
4. **Check Event Filter Triggers**: Examine what triggers the subscription. Common malicious triggers include system startup (Win32_ProcessStartTrace), user logon, or timer-based execution intervals.
5. **Investigate WmiPrvSe.exe Child Processes**: When a WMI subscription fires, the action is executed by WmiPrvSe.exe. Hunt for unusual child processes of WmiPrvSe.exe.
6. **Correlate with MOF Compilation**: Detect `mofcomp.exe` usage which compiles MOF files to create WMI subscriptions programmatically.
7. **Validate and Respond**: Confirm malicious subscriptions, remove them, and trace back to the initial infection vector.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1546.003 | Event Triggered Execution: WMI Event Subscription |
| __EventFilter | WMI class defining the trigger condition |
| __EventConsumer | WMI class defining the action to perform |
| __FilterToConsumerBinding | Links a filter to a consumer |
| ActiveScriptEventConsumer | Consumer that runs VBScript or JScript |
| CommandLineEventConsumer | Consumer that executes command lines |
| WmiPrvSe.exe | WMI Provider Host that executes subscription actions |
| MOF File | Managed Object Format used to define WMI objects |

## Detection Queries

### Splunk -- WMI Subscription Creation via Sysmon
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval event_type=case(EventCode=19, "EventFilter", EventCode=20, "EventConsumer", EventCode=21, "FilterToConsumerBinding")
| table _time Computer User event_type EventNamespace Name Query Destination Operation
```

### Splunk -- WMI Subscription via Windows Event 5861
```spl
index=wineventlog source="Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| table _time Computer NamespaceName Operation PossibleCause
```

### PowerShell -- Enumerate WMI Subscriptions
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### KQL -- WmiPrvSe.exe Spawning Suspicious Children
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Sigma Rule
```yaml
title: WMI Event Subscription Persistence
status: stable
logsource:
    product: windows
    category: wmi_event
detection:
    selection_consumer:
        EventID: 20
        Destination|contains:
            - 'ActiveScriptEventConsumer'
            - 'CommandLineEventConsumer'
    condition: selection_consumer
level: high
tags:
    - attack.persistence
    - attack.t1546.003
```

## Common Scenarios

1. **APT29 WMI Persistence**: Creates an ActiveScriptEventConsumer that executes a VBScript backdoor on system startup, surviving reboots and credential resets.
2. **Turla WMI Backdoor**: Uses Win32_ProcessStartTrace filter combined with CommandLineEventConsumer for covert command execution.
3. **FIN8 WMI Timer**: Interval-based __IntervalTimerEvent triggering encoded PowerShell downloads every 30 minutes.
4. **MOF-Based Installation**: Adversary drops a .mof file and compiles it with `mofcomp.exe` to silently create persistent subscriptions.

## Output Format

```
Hunt ID: TH-WMI-[DATE]-[SEQ]
Host: [Hostname]
Subscription Name: [Filter/Consumer name]
Filter Query: [WQL trigger condition]
Consumer Type: [ActiveScript/CommandLine]
Consumer Action: [Script content or command]
Binding: [Filter-to-Consumer link]
Created: [Timestamp]
User Context: [SYSTEM/User]
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
