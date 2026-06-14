---
name: cb-hunting-for-persistence-mechanisms-in-windows
skill_id: cb-hunting-for-persistence-mechanisms-in-windows
journal_id: CB-SKL-239
description: Cold-box analyst playbook — Hunting For Persistence Mechanisms In Windows.
  Systematically hunt for adversary persistence mechanisms across Windows endpoints
  including registry, services, startup folders, and WMI subscriptions.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- mitre-attack
- persistence
- windows
- registry
- siem
- proactive-detection
cold_box_version: 2
inspired_by: hunting-for-persistence-mechanisms-in-windows
---

# Hunting For Persistence Mechanisms In Windows (cold-box)

> **Journal ID:** `CB-SKL-239` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-239`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-persistence-mechanisms-in-windows")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-persistence-mechanisms-in-windows")` → note **`CB-SKL-239`**
2. `log_skill(case_id, journal_id="CB-SKL-239", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-239` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- During periodic proactive threat hunts for dormant backdoors
- After an incident to identify all persistence mechanisms an attacker planted
- When investigating unusual services, scheduled tasks, or startup entries
- When threat intel reports describe new persistence techniques in the wild
- During security posture assessments to identify unauthorized persistent software

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `autoruns` | `SIFT-176` | no | no |
| `RECmd` | `SIFT-224` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-239] powershell per playbook step",
  "why": "Executing cb-hunting-for-persistence-mechanisms-in-windows \u2014 see Procedure section",
  "extra_args": []
}
```

### `autoruns` → `SIFT-176`

```json
{
  "tool_id": "SIFT-176",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-239] autoruns per playbook step",
  "why": "Executing cb-hunting-for-persistence-mechanisms-in-windows \u2014 see Procedure section",
  "extra_args": []
}
```

### `RECmd` → `SIFT-224`

```json
{
  "tool_id": "SIFT-224",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-239] RECmd per playbook step",
  "why": "Executing cb-hunting-for-persistence-mechanisms-in-windows \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-239] file per playbook step",
  "why": "Executing cb-hunting-for-persistence-mechanisms-in-windows \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-239` (`cb-hunting-for-persistence-mechanisms-in-windows`)

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

- During periodic proactive threat hunts for dormant backdoors
- After an incident to identify all persistence mechanisms an attacker planted
- When investigating unusual services, scheduled tasks, or startup entries
- When threat intel reports describe new persistence techniques in the wild
- During security posture assessments to identify unauthorized persistent software

## Prerequisites

- Sysmon deployed with Event IDs 12/13/14 (Registry), 19/20/21 (WMI), 1 (Process Creation)
- Windows Security Event forwarding for 4697 (Service Install), 4698 (Scheduled Task)
- EDR with registry and file monitoring capabilities
- PowerShell script block logging enabled (Event ID 4104)
- Autoruns or equivalent baseline of legitimate persistent entries

## Workflow

1. **Enumerate Known Persistence Locations**: Build a comprehensive list of Windows persistence points (Run keys, services, scheduled tasks, WMI, startup folder, DLL search order, COM hijacks, AppInit DLLs, Image File Execution Options).
2. **Collect Endpoint Data**: Use EDR, Sysmon, or Velociraptor to collect current persistence artifacts from endpoints across the environment.
3. **Baseline Legitimate Persistence**: Compare collected data against known-good baselines (Autoruns snapshots, GPO-deployed entries, SCCM configurations).
4. **Identify Anomalies**: Flag new, unsigned, or unknown entries in persistence locations that deviate from the baseline.
5. **Investigate Suspicious Entries**: For each anomaly, examine the binary it points to, its digital signature, file hash, and creation timestamp.
6. **Correlate with Process Activity**: Link persistence entries to process execution, network activity, and user login events.
7. **Document and Remediate**: Record findings, remove malicious persistence, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1547.001 | Registry Run Keys / Startup Folder |
| T1543.003 | Windows Service (Create or Modify) |
| T1053.005 | Scheduled Task |
| T1546.003 | WMI Event Subscription |
| T1546.015 | Component Object Model (COM) Hijacking |
| T1546.012 | Image File Execution Options Injection |
| T1546.010 | AppInit DLLs |
| T1547.004 | Winlogon Helper DLL |
| T1547.005 | Security Support Provider |
| T1574.001 | DLL Search Order Hijacking |
| TA0003 | Persistence Tactic |
| Autoruns | Sysinternals tool showing persistent entries |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysinternals Autoruns | Comprehensive persistence enumeration |
| Velociraptor | Endpoint-wide persistence artifact collection |
| CrowdStrike Falcon | Real-time persistence monitoring |
| Sysmon | Registry and WMI event monitoring |
| OSQuery | SQL-based persistence queries |
| RECmd | Registry Explorer for forensic analysis |
| Splunk | SIEM correlation of persistence events |

## Common Scenarios

1. **Registry Run Key Backdoor**: Malware adds `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry pointing to payload in `%APPDATA%`.
2. **WMI Event Subscription**: Adversary creates WMI consumer/filter pair that executes PowerShell on system boot.
3. **Malicious Service**: Attacker creates Windows service with `sc create` pointing to a backdoor binary.
4. **COM Object Hijack**: Legitimate COM CLSID InprocServer32 path replaced with malicious DLL.
5. **IFEO Debugger Injection**: Image File Execution Options key set with debugger pointing to implant for common utilities.

## Output Format

```
Hunt ID: TH-PERSIST-[DATE]-[SEQ]
Persistence Type: [Registry/Service/Task/WMI/COM/Other]
MITRE Technique: T1547.xxx / T1543.xxx / T1053.xxx
Location: [Full registry key / service name / task path]
Value: [Binary path / command line]
Host(s): [Affected endpoints]
Signed: [Yes/No]
Hash: [SHA256]
Creation Time: [Timestamp]
Risk Level: [Critical/High/Medium/Low]
Verdict: [Malicious/Suspicious/Benign]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
