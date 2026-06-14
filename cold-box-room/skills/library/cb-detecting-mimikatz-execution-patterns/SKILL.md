---
name: cb-detecting-mimikatz-execution-patterns
skill_id: cb-detecting-mimikatz-execution-patterns
journal_id: CB-SKL-197
description: Cold-box analyst playbook — Detecting Mimikatz Execution Patterns. Detect
  Mimikatz execution through command-line patterns, LSASS access signatures, binary
  indicators, and in-memory detection of known modules.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- memory
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- mitre-attack
- mimikatz
- credential-dumping
- edr
- t1003
- proactive-detection
cold_box_version: 2
inspired_by: detecting-mimikatz-execution-patterns
---

# Detecting Mimikatz Execution Patterns (cold-box)

> **Journal ID:** `CB-SKL-197` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-197`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-mimikatz-execution-patterns")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-mimikatz-execution-patterns")` → note **`CB-SKL-197`**
2. `log_skill(case_id, journal_id="CB-SKL-197", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-197` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When proactively hunting for indicators of detecting mimikatz execution patterns in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Tool map (SIFT via MCP)

**Execution mode:** `partial` — Tools mapped but some are unavailable — check `describe_sift_tool` / `list_sift_tools`.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-197] powershell per playbook step",
  "why": "Executing cb-detecting-mimikatz-execution-patterns \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-197` (`cb-detecting-mimikatz-execution-patterns`)

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

- When proactively hunting for indicators of detecting mimikatz execution patterns in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Prerequisites

- EDR platform with process and network telemetry (CrowdStrike, MDE, SentinelOne)
- SIEM with relevant log data ingested (Splunk, Elastic, Sentinel)
- Sysmon deployed with comprehensive configuration
- Windows Security Event Log forwarding enabled
- Threat intelligence feeds for IOC correlation

## Workflow

1. **Formulate Hypothesis**: Define a testable hypothesis based on threat intelligence or ATT&CK gap analysis.
2. **Identify Data Sources**: Determine which logs and telemetry are needed to validate or refute the hypothesis.
3. **Execute Queries**: Run detection queries against SIEM and EDR platforms to collect relevant events.
4. **Analyze Results**: Examine query results for anomalies, correlating across multiple data sources.
5. **Validate Findings**: Distinguish true positives from false positives through contextual analysis.
6. **Correlate Activity**: Link findings to broader attack chains and threat actor TTPs.
7. **Document and Report**: Record findings, update detection rules, and recommend response actions.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1003.001 | LSASS Memory |
| T1003.006 | DCSync |
| T1558.003 | Kerberoasting |
| T1558.001 | Golden Ticket |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | EDR telemetry and threat detection |
| Microsoft Defender for Endpoint | Advanced hunting with KQL |
| Splunk Enterprise | SIEM log analysis with SPL queries |
| Elastic Security | Detection rules and investigation timeline |
| Sysmon | Detailed Windows event monitoring |
| Velociraptor | Endpoint artifact collection and hunting |
| Sigma Rules | Cross-platform detection rule format |

## Common Scenarios

1. **Scenario 1**: Standard sekurlsa::logonpasswords credential dump
2. **Scenario 2**: PowerShell Invoke-Mimikatz reflective loading
3. **Scenario 3**: DCSync from non-DC host
4. **Scenario 4**: Golden ticket creation for persistence

## Output Format

```
Hunt ID: TH-DETECT-[DATE]-[SEQ]
Technique: T1003.001
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
