---
name: cb-detecting-lateral-movement-with-splunk
skill_id: cb-detecting-lateral-movement-with-splunk
journal_id: CB-SKL-195
description: Cold-box analyst playbook — Detecting Lateral Movement With Splunk. Detect
  adversary lateral movement across networks using Splunk SPL queries against Windows
  authentication logs, SMB traffic, and remote service abuse.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- mitre-attack
- lateral-movement
- splunk
- siem
- proactive-detection
- ta0008
cold_box_version: 2
inspired_by: detecting-lateral-movement-with-splunk
---

# Detecting Lateral Movement With Splunk (cold-box)

> **Journal ID:** `CB-SKL-195` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-195`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-lateral-movement-with-splunk")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-lateral-movement-with-splunk")` → note **`CB-SKL-195`**
2. `log_skill(case_id, journal_id="CB-SKL-195", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-195` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for adversary movement between compromised systems
- After detecting credential theft to trace subsequent lateral activity
- When investigating unusual authentication patterns across the network
- During incident response to scope the breadth of compromise
- When proactively hunting for TA0008 (Lateral Movement) techniques

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — Limited SIFT coverage; treat remaining steps as reference.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `wmic` | `SIFT-186` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-195] powershell per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-splunk \u2014 see Procedure section",
  "extra_args": []
}
```

### `wmic` → `SIFT-186`

```json
{
  "tool_id": "SIFT-186",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-195] wmic per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-splunk \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-195` (`cb-detecting-lateral-movement-with-splunk`)

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

- When hunting for adversary movement between compromised systems
- After detecting credential theft to trace subsequent lateral activity
- When investigating unusual authentication patterns across the network
- During incident response to scope the breadth of compromise
- When proactively hunting for TA0008 (Lateral Movement) techniques

## Prerequisites

- Splunk Enterprise or Splunk Cloud with Windows event data ingested
- Windows Security Event Logs forwarded (4624, 4625, 4648, 4672, 4768, 4769)
- Sysmon deployed for process creation and network connection data
- Network flow data or firewall logs for SMB/RDP/WinRM correlation
- Active Directory user and group membership reference data

## Workflow

1. **Define Lateral Movement Scope**: Identify which lateral movement techniques to hunt (RDP, SMB/Admin Shares, WinRM, PsExec, WMI, DCOM, SSH).
2. **Query Authentication Events**: Use SPL to search for Type 3 (Network) and Type 10 (RemoteInteractive) logons across the environment.
3. **Build Authentication Graphs**: Map source-to-destination authentication relationships to identify unusual connection patterns.
4. **Detect First-Time Relationships**: Identify new source-destination pairs that have not been seen in the historical baseline.
5. **Correlate with Process Activity**: Link authentication events to subsequent process creation on destination hosts.
6. **Identify Anomalous Patterns**: Flag lateral movement to sensitive servers, unusual hours, service account misuse, or rapid multi-host access.
7. **Report and Contain**: Document lateral movement path, affected systems, and coordinate containment response.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1021 | Remote Services (parent technique) |
| T1021.001 | Remote Desktop Protocol (RDP) |
| T1021.002 | SMB/Windows Admin Shares |
| T1021.003 | Distributed COM (DCOM) |
| T1021.004 | SSH |
| T1021.006 | Windows Remote Management (WinRM) |
| T1570 | Lateral Tool Transfer |
| T1047 | Windows Management Instrumentation |
| T1569.002 | Service Execution (PsExec) |
| Logon Type 3 | Network logon (SMB, WinRM, mapped drives) |
| Logon Type 10 | Remote Interactive (RDP) |
| Event ID 4624 | Successful logon |
| Event ID 4648 | Explicit credential logon (runas, PsExec) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Splunk Enterprise | SIEM for log aggregation and SPL queries |
| Splunk Enterprise Security | Threat detection and notable events |
| Windows Event Forwarding | Centralize Windows logs |
| Sysmon | Detailed process and network telemetry |
| BloodHound | AD attack path analysis |
| PingCastle | AD security assessment |

## Common Scenarios

1. **PsExec Lateral Movement**: Adversary uses PsExec to execute commands on remote systems via SMB, generating Type 3 logon with ADMIN$ share access.
2. **RDP Pivoting**: Attacker RDPs to internal systems using stolen credentials, creating Type 10 logon events.
3. **WMI Remote Execution**: Adversary uses WMIC process call create to spawn processes on remote hosts.
4. **WinRM PowerShell Remoting**: Attacker uses Enter-PSSession or Invoke-Command to execute code on remote systems.
5. **Pass-the-Hash via SMB**: Compromised NTLM hashes used to authenticate to remote systems without knowing the plaintext password.

## Output Format

```
Hunt ID: TH-LATMOV-[DATE]-[SEQ]
Movement Type: [RDP/SMB/WinRM/WMI/DCOM/PsExec]
Source Host: [Hostname/IP]
Destination Host: [Hostname/IP]
Account Used: [Username]
Logon Type: [3/10/other]
First Seen: [Timestamp]
Event Count: [Number of events]
Risk Level: [Critical/High/Medium/Low]
Lateral Movement Path: [A -> B -> C -> D]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
