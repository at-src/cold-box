---
name: cb-hunting-for-process-injection-techniques
skill_id: cb-hunting-for-process-injection-techniques
journal_id: CB-SKL-053
description: Cold-box analyst playbook — Hunting For Process Injection Techniques.
  Detect process injection techniques (T1055) including CreateRemoteThread, process
  hollowing, and DLL injection via Sysmon Event IDs 8 and 10 and EDR process telemetry
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- general
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- process-injection
- t1055
- sysmon
- createremotethread
- dll-injection
- edr
- threat-hunting
cold_box_version: 2
inspired_by: hunting-for-process-injection-techniques
---

# Hunting For Process Injection Techniques (cold-box)

> **Journal ID:** `CB-SKL-053` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-053`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-process-injection-techniques")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-process-injection-techniques")` → note **`CB-SKL-053`**
2. `log_skill(case_id, journal_id="CB-SKL-053", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-053` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for process injection techniques
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

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
## {timestamp} — skill `CB-SKL-053` (`cb-hunting-for-process-injection-techniques`)

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

## Overview

Process injection (MITRE ATT&CK T1055) allows adversaries to execute code in the address space of another process, enabling defense evasion and privilege escalation. This skill detects injection techniques via Sysmon Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess with suspicious access rights), and analysis of source-target process relationships to distinguish legitimate from malicious injection.


## When to Use

- When investigating security incidents that require hunting for process injection techniques
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Sysmon installed with Event IDs 8 and 10 enabled
- Process creation logs (Sysmon Event ID 1 or Windows 4688)
- Python 3.8+ with standard library
- JSON-formatted Sysmon event logs

## Steps

1. **Parse Sysmon Events** — Ingest Event IDs 1, 8, and 10 from JSON log files
2. **Detect CreateRemoteThread** — Flag Event ID 8 with suspicious source-target process pairs
3. **Analyze ProcessAccess Rights** — Identify Event ID 10 with dangerous access masks (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD)
4. **Build Process Relationship Graph** — Map source-to-target injection relationships
5. **Filter Known Legitimate Pairs** — Exclude known benign injection patterns (AV, debuggers, system processes)
6. **Score Injection Severity** — Apply risk scoring based on source process, target process, and access rights
7. **Generate Hunt Report** — Produce structured report with MITRE sub-technique mapping

## Expected Output

- JSON report of detected injection events with severity scores
- Process injection relationship graph
- MITRE ATT&CK sub-technique mapping (T1055.001-T1055.012)
- False positive exclusion recommendations

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
