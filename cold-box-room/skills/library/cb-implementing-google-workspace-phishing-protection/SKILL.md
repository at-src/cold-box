---
name: cb-implementing-google-workspace-phishing-protection
skill_id: cb-implementing-google-workspace-phishing-protection
journal_id: CB-SKL-262
description: Cold-box analyst playbook — Implementing Google Workspace Phishing Protection.
  Configure Google Workspace advanced phishing and malware protection settings including
  pre-delivery scanning, attachment protection, spoofing detection, and Enhanced Safe
  Browsing.
domain: cold-box
subdomain: phishing-defense
tier: adjacent
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- google-workspace
- gmail
- phishing
- email-security
- safe-browsing
- anti-spoofing
- admin-console
cold_box_version: 2
inspired_by: implementing-google-workspace-phishing-protection
---

# Implementing Google Workspace Phishing Protection (cold-box)

> **Journal ID:** `CB-SKL-262` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-262`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-google-workspace-phishing-protection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-google-workspace-phishing-protection")` → note **`CB-SKL-262`**
2. `log_skill(case_id, journal_id="CB-SKL-262", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-262` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing google workspace phishing protection capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-262] file per playbook step",
  "why": "Executing cb-implementing-google-workspace-phishing-protection \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-262` (`cb-implementing-google-workspace-phishing-protection`)

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
Google Workspace provides advanced phishing and malware protection through the Admin Console under Apps > Google Workspace > Gmail > Safety. Key features include Enhanced Pre-Delivery Scanning that examines messages more thoroughly before they reach inboxes, attachment and link protection that scans for malware and checks against known malicious sites, and spoofing detection for domain and employee name impersonation. Google's Advanced Protection Program (APP) provides the strongest account security for high-privilege users.


## When to Use

- When deploying or configuring implementing google workspace phishing protection capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites
- Google Workspace Business Standard or higher license
- Gmail Settings administrator privilege
- Understanding of organizational email flow and third-party integrations
- Access to Google Admin Console (admin.google.com)
- DNS management access for SPF, DKIM, DMARC configuration

## Workflow

### Step 1: Configure Advanced Phishing Protection
- Navigate to Admin Console > Apps > Google Workspace > Gmail > Safety
- Enable "Protect against domain spoofing based on similar domain names"
- Enable "Protect against spoofing of employee names"
- Enable "Protect against inbound emails spoofing your domain"
- Set action for detected spoofing: quarantine or move to spam with warning banner
- Apply settings to all organizational units or specific high-risk groups

### Step 2: Enable Enhanced Pre-Delivery Scanning
- In Safety settings, enable "Enhanced pre-delivery message scanning"
- This adds additional delay (seconds) to scan messages more thoroughly
- Configure to detect phishing attempts that evade initial filters
- Enable "Identify links behind shortened URLs"
- Enable "Scan linked images" for image-based phishing detection

### Step 3: Configure Attachment Protection
- Enable "Protect against encrypted attachments from untrusted senders"
- Enable "Protect against attachments with scripts from untrusted senders"
- Enable "Protect against anomalous attachment types in emails"
- Configure action: warn users, move to spam, or quarantine
- Create exceptions for known legitimate encrypted file senders

### Step 4: Enable Enhanced Safe Browsing
- Navigate to Admin Console > Security > Gmail Enhanced Safe Browsing
- Enable Enhanced Safe Browsing for the organization (off by default)
- This provides real-time protection against phishing URLs in emails
- Configure at organizational unit level for phased rollout
- Monitor user feedback for false positive impact

### Step 5: Enroll High-Risk Users in Advanced Protection Program
- Identify high-privilege accounts: super admins, executives, finance leadership
- Enroll users in Google's Advanced Protection Program (APP)
- APP requires FIDO2 security keys for authentication
- APP blocks third-party app access unless explicitly approved
- APP provides enhanced scanning for Gmail and Drive downloads

### Step 6: Configure Email Authentication
- Publish SPF record: `v=spf1 include:_spf.google.com ~all`
- Enable DKIM signing in Admin Console > Apps > Google Workspace > Gmail > Authenticate email
- Configure DMARC with monitoring: `v=DMARC1; p=none; rua=mailto:dmarc@company.com`
- Progress DMARC to enforcement per organizational readiness

## Tools & Resources
- **Google Admin Console**: Central management for all security settings
- **Google Workspace Security Investigation Tool**: Threat analysis and response
- **Google Security Center**: Security health recommendations and dashboard
- **Gmail Security Sandbox**: Attachment detonation for enterprise licenses
- **Google Advanced Protection Program**: Strongest account security

## Validation
- Spoofing protection blocks test email with lookalike domain
- Pre-delivery scanning catches test phishing with delayed weaponization
- Attachment protection warns on test encrypted attachment
- Enhanced Safe Browsing blocks known phishing URL clicked in email
- APP-enrolled accounts reject non-FIDO2 authentication attempts
- SPF, DKIM, DMARC all pass for outbound messages

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
