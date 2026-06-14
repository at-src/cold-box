---
name: cb-implementing-siem-correlation-rules-for-apt
skill_id: cb-implementing-siem-correlation-rules-for-apt
journal_id: CB-SKL-060
description: 'Cold-box analyst playbook — Implementing Siem Correlation Rules For
  Apt. Write multi-event correlation rules that detect APT lateral movement by chaining
  Windows authentication events, process execution telemetry, and network connection
  logs across hosts. Uses Splunk SPL and Sigma rule format to correlate Event '
domain: cold-box
subdomain: security-operations
tier: core
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- siem
- correlation-rules
- apt-detection
- lateral-movement
- windows-event-logs
- security-operations
cold_box_version: 2
inspired_by: implementing-siem-correlation-rules-for-apt
---

# Implementing Siem Correlation Rules For Apt (cold-box)

> **Journal ID:** `CB-SKL-060` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-060`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-siem-correlation-rules-for-apt")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-siem-correlation-rules-for-apt")` → note **`CB-SKL-060`**
2. `log_skill(case_id, journal_id="CB-SKL-060", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-060` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing siem correlation rules for apt capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — procedure steps target external platforms (SIEM, cloud, etc.).
Use for investigation guidance; log `{journal_id}` and note gaps when SIFT cannot run a step.

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

_No SIFT tools mapped for this playbook on cold-box._
Follow the procedure for reasoning; document external-platform gaps in the journal.

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-060` (`cb-implementing-siem-correlation-rules-for-apt`)

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

- When deploying or configuring implementing siem correlation rules for apt capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests pyyaml sigma-cli`
2. Connect to the Splunk REST API and define correlation searches that chain multiple event types across hosts.
3. Build Sigma rules in YAML that express multi-step detection logic for lateral movement patterns:
   - RDP logon (4624 LogonType=10) followed by service installation (7045) on same target within 15 minutes
   - Pass-the-Hash: NTLM logon (4624 LogonType=3) followed by process creation (4688) of admin tools
   - PsExec-style: Named pipe creation (Sysmon 17/18) correlated with remote service creation (7045)
4. Convert Sigma rules to Splunk SPL using `sigma-cli convert`.
5. Deploy correlation searches to Splunk ES via the REST API.
6. Run the agent to generate and install correlation rules, then audit existing rules for coverage gaps.

```bash
python scripts/agent.py --splunk-url https://localhost:8089 --username admin --password changeme --output correlation_report.json
```

## Examples

### Detect RDP Lateral Movement Chain
```
index=wineventlog (EventCode=4624 Logon_Type=10) OR (EventCode=7045)
| transaction Computer maxspan=15m startswith=(EventCode=4624) endswith=(EventCode=7045)
| where eventcount >= 2
| table _time Computer Account_Name ServiceName
```

### Sigma Rule for PsExec Lateral Movement
```yaml
title: PsExec Lateral Movement Detection
logsource:
  product: windows
  service: sysmon
detection:
  pipe_created:
    EventID: 17
    PipeName|startswith: '\PSEXESVC'
  service_installed:
    EventID: 7045
    ServiceFileName|contains: 'PSEXESVC'
  timeframe: 5m
  condition: pipe_created | near service_installed
level: high
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
