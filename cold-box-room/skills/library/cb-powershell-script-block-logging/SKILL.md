---
name: cb-powershell-script-block-logging
skill_id: cb-powershell-script-block-logging
journal_id: CB-SKL-102
description: Cold-box analyst playbook — Powershell Script Block Logging. Parse Windows
  PowerShell Script Block Logs (Event ID 4104) from EVTX files to detect obfuscated
  commands, encoded payloads, and living-off-the-land techniques. Uses python-evtx
  to extract and reconstruct multi-block scripts, applies entropy
domain: cold-box
subdomain: security-operations
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- powershell
- script-block-logging
- event-id-4104
- obfuscation-detection
- windows-forensics
- endpoint-security
cold_box_version: 2
inspired_by: analyzing-powershell-script-block-logging
---

# Powershell Script Block Logging (cold-box)

> **Journal ID:** `CB-SKL-102` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-102`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-powershell-script-block-logging")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-powershell-script-block-logging")` → note **`CB-SKL-102`**
2. `log_skill(case_id, journal_id="CB-SKL-102", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-102` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing powershell script block logging
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

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
  "purpose": "[CB-SKL-102] powershell per playbook step",
  "why": "Executing cb-powershell-script-block-logging \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-102] file per playbook step",
  "why": "Executing cb-powershell-script-block-logging \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-102` (`cb-powershell-script-block-logging`)

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

- When investigating security incidents that require analyzing powershell script block logging
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install python-evtx lxml`
2. Collect PowerShell Operational logs: `Microsoft-Windows-PowerShell%4Operational.evtx`
3. Parse Event ID 4104 entries using python-evtx to extract ScriptBlockText, ScriptBlockId, and MessageNumber/MessageTotal for multi-part script reconstruction.
4. Apply detection heuristics:
   - Base64-encoded commands (`-EncodedCommand`, `FromBase64String`)
   - Download cradles (`DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`)
   - AMSI bypass patterns (`AmsiUtils`, `amsiInitFailed`)
   - Obfuscation indicators (high entropy, tick-mark insertion, string concatenation)
5. Generate a report with reconstructed scripts, risk scores, and MITRE ATT&CK mappings.

```bash
python scripts/agent.py --evtx-file /path/to/PowerShell-Operational.evtx --output ps_analysis.json
```

## Examples

### Detect Encoded Command Execution
```python
import base64
if "-encodedcommand" in script_text.lower():
    encoded = script_text.split()[-1]
    decoded = base64.b64decode(encoded).decode("utf-16-le")
```

### Reconstruct Multi-Block Script
Scripts split across multiple 4104 events share a `ScriptBlockId`. Concatenate blocks ordered by `MessageNumber` to recover the full script.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
