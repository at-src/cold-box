---
name: cb-detecting-wmi-persistence
skill_id: cb-detecting-wmi-persistence
journal_id: CB-SKL-033
description: Cold-box analyst playbook — Detecting Wmi Persistence. Detect WMI event
  subscription persistence by analyzing Sysmon Event IDs 19, 20, and 21 for malicious
  EventFilter, EventConsumer, and FilterToConsumerBinding creation.
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- general
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- wmi
- persistence
- sysmon
- t1546.003
- mitre-attack
- windows
- dfir
cold_box_version: 2
inspired_by: detecting-wmi-persistence
---

# Detecting Wmi Persistence (cold-box)

> **Journal ID:** `CB-SKL-033` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-033`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-wmi-persistence")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-wmi-persistence")` → note **`CB-SKL-033`**
2. `log_skill(case_id, journal_id="CB-SKL-033", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-033` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for WMI event subscription persistence (MITRE ATT&CK T1546.003)
- After detecting suspicious WMI activity in endpoint telemetry
- During incident response to identify attacker persistence mechanisms
- When Sysmon alerts trigger on Event IDs 19, 20, or 21
- During purple team exercises testing WMI-based persistence

## Tool map (SIFT via MCP)

**Execution mode:** `partial` — Tools mapped but some are unavailable — check `describe_sift_tool` / `list_sift_tools`.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `autoruns` | `SIFT-176` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-033] powershell per playbook step",
  "why": "Executing cb-detecting-wmi-persistence \u2014 see Procedure section",
  "extra_args": []
}
```

### `autoruns` → `SIFT-176`

```json
{
  "tool_id": "SIFT-176",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-033] autoruns per playbook step",
  "why": "Executing cb-detecting-wmi-persistence \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-033` (`cb-detecting-wmi-persistence`)

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

- When hunting for WMI event subscription persistence (MITRE ATT&CK T1546.003)
- After detecting suspicious WMI activity in endpoint telemetry
- During incident response to identify attacker persistence mechanisms
- When Sysmon alerts trigger on Event IDs 19, 20, or 21
- During purple team exercises testing WMI-based persistence

## Prerequisites

- Sysmon v6.1+ deployed with WMI event logging enabled (Event IDs 19, 20, 21)
- Windows Security Event Log forwarding configured
- SIEM with Sysmon data ingested (Splunk, Elastic, Sentinel)
- PowerShell access for WMI enumeration on endpoints
- Sysinternals Autoruns for manual WMI subscription review

## Workflow

1. **Collect Telemetry**: Parse Sysmon Event IDs 19 (WmiEventFilter), 20 (WmiEventConsumer), 21 (WmiEventConsumerToFilter).
2. **Identify Suspicious Consumers**: Flag CommandLineEventConsumer and ActiveScriptEventConsumer types executing code.
3. **Analyze Event Filters**: Examine WQL queries in EventFilters for process start triggers or timer-based execution.
4. **Correlate Bindings**: Match FilterToConsumerBindings linking suspicious filters to consumers.
5. **Check Persistence Locations**: Query WMI namespaces root\subscription and root\default for active subscriptions.
6. **Validate Findings**: Cross-reference with known-good WMI subscriptions (SCCM, AV products).
7. **Document and Remediate**: Remove malicious subscriptions and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| Sysmon Event 19 | WmiEventFilter creation detected |
| Sysmon Event 20 | WmiEventConsumer creation detected |
| Sysmon Event 21 | WmiEventConsumerToFilter binding detected |
| T1546.003 | Event Triggered Execution: WMI Event Subscription |
| CommandLineEventConsumer | Executes system commands when filter triggers |
| ActiveScriptEventConsumer | Runs VBScript/JScript when filter triggers |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Windows event monitoring for WMI activity |
| WMI Explorer | GUI tool for browsing WMI namespaces |
| Autoruns | Sysinternals tool listing persistence mechanisms |
| PowerShell Get-WMIObject | Enumerate WMI event subscriptions |
| Splunk | SIEM analysis of Sysmon WMI events |
| Velociraptor | Endpoint WMI artifact collection |

## Output Format

```
Hunt ID: TH-WMI-[DATE]-[SEQ]
Technique: T1546.003
Host: [Hostname]
Event Type: [EventFilter|EventConsumer|Binding]
Consumer Type: [CommandLine|ActiveScript]
WQL Query: [Filter query text]
Command: [Executed command or script]
Risk Level: [Critical/High/Medium/Low]
Recommended Action: [Remove subscription, investigate lateral movement]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
