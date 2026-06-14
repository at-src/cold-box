---
name: cb-hunting-for-ntlm-relay-attacks
skill_id: cb-hunting-for-ntlm-relay-attacks
journal_id: CB-SKL-238
description: Cold-box analyst playbook — Hunting For Ntlm Relay Attacks. Detect NTLM
  relay attacks by analyzing Windows Event 4624 logon type 3 with NTLMSSP authentication,
  identifying IP-to-hostname mismatches, Responder traffic signatures, SMB signing
  status, and suspicious authentication patterns across the d
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- general
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- NTLM-relay
- Windows-events
- Event-4624
- NTLMSSP
- Responder
- SMB-signing
- credential-access
- T1557.001
- Active-Directory
cold_box_version: 2
inspired_by: hunting-for-ntlm-relay-attacks
---

# Hunting For Ntlm Relay Attacks (cold-box)

> **Journal ID:** `CB-SKL-238` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-238`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-ntlm-relay-attacks")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-ntlm-relay-attacks")` → note **`CB-SKL-238`**
2. `log_skill(case_id, journal_id="CB-SKL-238", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-238` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for ntlm relay attacks
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
## {timestamp} — skill `CB-SKL-238` (`cb-hunting-for-ntlm-relay-attacks`)

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

NTLM relay attacks intercept and forward NTLM authentication messages to gain unauthorized access to network resources. Attackers use tools like Responder for LLMNR/NBT-NS poisoning and ntlmrelayx for credential relay. This skill detects relay activity by querying Windows Security Event 4624 (successful logon) for type 3 network logons with NTLMSSP authentication, identifying mismatches between WorkstationName and source IpAddress, detecting rapid multi-host authentication from single accounts, and auditing SMB signing configuration across domain hosts.


## When to Use

- When investigating security incidents that require hunting for ntlm relay attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with Windows Event Log access or exported logs
- Windows Security audit logging enabled (Event ID 4624, 4625, 5145)
- Network access for SMB signing status checks

## Key Detection Areas

1. **IP-hostname mismatch** — WorkstationName in Event 4624 does not resolve to the source IpAddress
2. **NTLMSSP authentication** — logon events using NTLM instead of Kerberos from domain-joined hosts
3. **Machine account relay** — computer accounts (ending in $) authenticating from unexpected IPs
4. **Rapid authentication** — single account authenticating to multiple hosts within seconds
5. **Named pipe access** — Event 5145 showing access to Spoolss, lsarpc, netlogon, samr pipes
6. **SMB signing disabled** — hosts not enforcing SMB signing, enabling relay attacks

## Output

JSON report with suspected relay events, IP-hostname correlation anomalies, SMB signing audit results, and MITRE ATT&CK mapping to T1557.001.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
