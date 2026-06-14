---
name: cb-detecting-azure-lateral-movement
skill_id: cb-detecting-azure-lateral-movement
journal_id: CB-SKL-021
description: Cold-box analyst playbook — Detecting Azure Lateral Movement. Detect
  lateral movement in Azure AD/Entra ID environments using Microsoft Graph API audit
  logs, Azure Sentinel KQL hunting queries, and sign-in anomaly correlation to identify
  privilege escalation, token theft, and cross-tenant pivoting.
domain: cold-box
subdomain: cloud-security
tier: core
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- azure
- entra-id
- lateral-movement
- sentinel
- kql
- graph-api
- cloud-security
- threat-hunting
cold_box_version: 2
inspired_by: detecting-azure-lateral-movement
---

# Detecting Azure Lateral Movement (cold-box)

> **Journal ID:** `CB-SKL-021` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-021`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-azure-lateral-movement")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-azure-lateral-movement")` → note **`CB-SKL-021`**
2. `log_skill(case_id, journal_id="CB-SKL-021", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-021` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting azure lateral movement
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
## {timestamp} — skill `CB-SKL-021` (`cb-detecting-azure-lateral-movement`)

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

Lateral movement in Azure AD/Entra ID differs from on-premises environments. Attackers pivot through OAuth application consent grants, service principal abuse, cross-tenant access policies, and stolen refresh tokens rather than SMB/RDP connections. Detection requires correlating Microsoft Graph API audit logs, Azure AD sign-in logs, and Entra ID protection risk events using KQL queries in Microsoft Sentinel. This skill covers building detection analytics for common Azure lateral movement techniques including application impersonation, mailbox delegation abuse, and conditional access policy bypasses.


## When to Use

- When investigating security incidents that require detecting azure lateral movement
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Azure subscription with Microsoft Sentinel workspace configured
- Azure AD P2 or Entra ID P2 license for risk-based sign-in detection
- Microsoft Graph API permissions: AuditLog.Read.All, Directory.Read.All, SecurityEvents.Read.All
- Log Analytics workspace ingesting AuditLogs, SigninLogs, and AADServicePrincipalSignInLogs
- Familiarity with KQL (Kusto Query Language)

## Steps

### Step 1: Configure Log Ingestion

Enable diagnostic settings to stream Azure AD logs to Log Analytics:
- Sign-in logs (interactive and non-interactive)
- Audit logs (directory changes, app consent)
- Service principal sign-in logs
- Provisioning logs
- Risky users and risk detections

### Step 2: Build Detection Queries

Create KQL analytics rules in Sentinel for:
- Unusual service principal credential additions
- OAuth application consent grants to unknown apps
- Cross-tenant sign-ins from new tenants
- Token replay from different IP/user-agent combinations
- Mailbox delegation changes (FullAccess, SendAs)

### Step 3: Correlate Events

Chain multiple low-confidence indicators into high-confidence lateral movement detections by correlating sign-in anomalies with directory changes within time windows.

### Step 4: Automate Response

Create Sentinel playbooks (Logic Apps) to automatically revoke suspicious OAuth grants, disable compromised service principals, and enforce step-up authentication.

## Expected Output

JSON report containing detected lateral movement indicators, correlated event chains, affected identities, and recommended containment actions with MITRE ATT&CK technique mappings.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
