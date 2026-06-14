---
name: cb-detecting-email-account-compromise
skill_id: cb-detecting-email-account-compromise
journal_id: CB-SKL-023
description: Cold-box analyst playbook — Detecting Email Account Compromise. Detect
  compromised O365 and Google Workspace email accounts by analyzing inbox rule creation,
  suspicious sign-in locations, mail forwarding rules, and unusual API access patterns
  via Microsoft Graph and audit logs.
domain: cold-box
subdomain: incident-response
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- email-compromise
- office365
- microsoft-graph
- bec
- inbox-rules
- sign-in-analysis
- account-takeover
cold_box_version: 2
inspired_by: detecting-email-account-compromise
---

# Detecting Email Account Compromise (cold-box)

> **Journal ID:** `CB-SKL-023` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-023`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-email-account-compromise")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-email-account-compromise")` → note **`CB-SKL-023`**
2. `log_skill(case_id, journal_id="CB-SKL-023", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-023` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting email account compromise
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `strings` | `SIFT-044` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-023] powershell per playbook step",
  "why": "Executing cb-detecting-email-account-compromise \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-023] strings per playbook step",
  "why": "Executing cb-detecting-email-account-compromise \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-023` (`cb-detecting-email-account-compromise`)

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

Email account compromise (EAC) is a prevalent attack vector where adversaries gain unauthorized access to mailboxes to exfiltrate sensitive data, conduct business email compromise (BEC), or establish persistence through inbox rule manipulation. Attackers commonly create forwarding rules to siphon emails, delete rules to hide evidence, or use OAuth tokens for persistent access. Detection relies on analyzing Microsoft 365 Unified Audit Logs, Azure AD sign-in logs for impossible travel or suspicious locations, inbox rule creation events (Set-InboxRule, New-InboxRule), and Microsoft Graph API access patterns. Key indicators include forwarding rules to external addresses, rules that delete or move messages matching keywords like "invoice" or "payment", and sign-ins from unusual user agents such as python-requests.


## When to Use

- When investigating security incidents that require detecting email account compromise
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Microsoft 365 with Unified Audit Logging enabled
- Azure AD P1/P2 for risk detection APIs
- Python 3.9+ with `requests`, `msal` libraries
- Microsoft Graph API application registration with Mail.Read, AuditLog.Read.All permissions
- Understanding of OAuth2 client credential flows

## Steps

1. Export audit logs or connect to Microsoft Graph API using MSAL authentication
2. Query inbox rules for all monitored mailboxes via `/users/{id}/mailFolders/inbox/messageRules`
3. Analyze rules for external forwarding (ForwardTo, RedirectTo external addresses)
4. Detect suspicious rule patterns: deletion rules, keyword-matching rules targeting financial terms
5. Query sign-in logs via `/auditLogs/signIns` for unusual locations and impossible travel
6. Check for suspicious user agent strings (python-requests, PowerShell, curl)
7. Identify OAuth application consent grants for suspicious third-party apps
8. Correlate findings across users to detect campaign-level compromise
9. Generate compromise indicators report with severity scores

## Expected Output

A JSON report listing compromised or suspicious accounts, malicious inbox rules detected, impossible travel events, suspicious OAuth grants, and recommended containment actions with severity ratings.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
