---
name: cb-implementing-endpoint-dlp-controls
skill_id: cb-implementing-endpoint-dlp-controls
journal_id: CB-SKL-261
description: Cold-box analyst playbook — Implementing Endpoint Dlp Controls. Implements
  endpoint Data Loss Prevention (DLP) controls to detect and prevent sensitive data
  exfiltration through email, USB, cloud storage, and printing. Use when deploying
  DLP agents, creating content inspection policies, or preventing un
domain: cold-box
subdomain: endpoint-security
tier: adjacent
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- endpoint
- DLP
- data-loss-prevention
- data-protection
- content-inspection
cold_box_version: 2
inspired_by: implementing-endpoint-dlp-controls
---

# Implementing Endpoint Dlp Controls (cold-box)

> **Journal ID:** `CB-SKL-261` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-261`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-endpoint-dlp-controls")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-endpoint-dlp-controls")` → note **`CB-SKL-261`**
2. `log_skill(case_id, journal_id="CB-SKL-261", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-261` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Deploying endpoint DLP to prevent sensitive data (PII, PHI, PCI) from leaving the organization
- Configuring content inspection rules for email attachments, USB transfers, and cloud uploads
- Implementing Microsoft Purview DLP or Symantec DLP endpoint policies
- Meeting compliance requirements for data protection (GDPR, HIPAA, PCI DSS)

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
  "purpose": "[CB-SKL-261] file per playbook step",
  "why": "Executing cb-implementing-endpoint-dlp-controls \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-261` (`cb-implementing-endpoint-dlp-controls`)

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

Use this skill when:
- Deploying endpoint DLP to prevent sensitive data (PII, PHI, PCI) from leaving the organization
- Configuring content inspection rules for email attachments, USB transfers, and cloud uploads
- Implementing Microsoft Purview DLP or Symantec DLP endpoint policies
- Meeting compliance requirements for data protection (GDPR, HIPAA, PCI DSS)

**Do not use** for network DLP (inline proxy-based) or cloud-only DLP (CASB).

## Prerequisites

- Microsoft 365 E5 or standalone Microsoft Purview DLP license
- Microsoft Purview compliance portal access (compliance.microsoft.com)
- Sensitive Information Types (SITs) defined for organization data
- Endpoint onboarded to Microsoft Purview (via Intune or SCCM)

## Workflow

### Step 1: Define Sensitive Information Types

```
Microsoft Purview → Data Classification → Sensitive info types

Built-in SITs for common data:
- Credit card number (PCI)
- Social Security Number (PII)
- Health records (HIPAA)
- Passport number
- Bank account number

Custom SIT example (Employee ID):
  Pattern: EMP-[0-9]{6}
  Confidence: High
  Keywords: "employee id", "emp id", "staff number"
```

### Step 2: Create DLP Policy

```
Microsoft Purview → Data loss prevention → Policies → Create policy

Policy Configuration:
1. Template: Financial / Medical / PII (or custom)
2. Locations: Devices (endpoint DLP)
3. Conditions:
   - Content contains: Credit card numbers (min 5 instances)
   - OR Content contains: SSN (min 1 instance)
4. Actions:
   - Block: Prevent copy to USB, cloud, email
   - Audit: Log but allow (for initial deployment)
   - Notify: Show user notification with policy tip
5. User notifications:
   - "This file contains sensitive data and cannot be copied to this location"
   - Allow override with business justification (optional)
```

### Step 3: Configure Endpoint DLP Activities

```
Monitored endpoint activities:
- Upload to cloud service (OneDrive, Dropbox, Google Drive)
- Copy to removable media (USB drives)
- Copy to network share
- Print document
- Copy to clipboard
- Access by unallowed browser (non-managed browser)
- Access by unallowed app
- Copy to Remote Desktop session

For each activity, configure:
- Audit only (log the action)
- Block with override (user can justify and proceed)
- Block (prevent action entirely)
```

### Step 4: Deploy in Audit Mode

```
Deploy DLP policy in "Test mode with notifications" first:
1. Policy runs in audit mode for 2-4 weeks
2. Review DLP alerts in Activity Explorer
3. Identify false positives
4. Tune SIT patterns and conditions
5. Add exclusions for legitimate workflows
6. Switch to "Turn on the policy" (enforcement)
```

### Step 5: Monitor and Respond

```
Purview → Data loss prevention → Activity explorer

Key metrics:
- DLP policy matches per day/week
- Top matched sensitive info types
- Top users triggering DLP
- Top activities blocked (USB, cloud, email)
- Override rate (percentage of blocks overridden)

DLP incident response:
1. Review DLP alert with matched content
2. Verify sensitivity of detected data
3. Assess intent (accidental vs. intentional)
4. If intentional exfiltration → escalate to security incident
5. If accidental → educate user, refine policy
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **DLP** | Data Loss Prevention; technology that detects and prevents unauthorized transmission of sensitive data |
| **SIT** | Sensitive Information Type; pattern matching rules for identifying sensitive data (regex, keywords, ML classifiers) |
| **Policy Tip** | User-facing notification explaining why an action was blocked and how to request an override |
| **Content Inspection** | Deep inspection of file contents to identify sensitive data patterns |
| **Exact Data Match (EDM)** | DLP matching against a specific database of known sensitive values (exact SSNs, employee records) |

## Tools & Systems

- **Microsoft Purview DLP**: Cloud-managed endpoint DLP included in M365 E5
- **Symantec DLP (Broadcom)**: Enterprise DLP with endpoint, network, and cloud modules
- **Digital Guardian**: Endpoint DLP with data classification and protection
- **Forcepoint DLP**: Unified DLP platform with endpoint agent
- **Code42 Incydr**: Insider risk detection with file exfiltration monitoring

## Common Pitfalls

- **Over-blocking in enforcement mode**: Deploy DLP in audit mode first. Blocking common workflows without warning causes productivity loss.
- **Too many SIT false positives**: Phone numbers, dates, and random number sequences can match PCI/SSN patterns. Tune confidence levels and require corroborating keywords.
- **Ignoring user education**: DLP is most effective when users understand why data is protected. Policy tips should explain the restriction and provide approved alternatives.
- **Not monitoring overrides**: If users frequently override DLP blocks, the policy is either too restrictive or users are ignoring data protection requirements. Review override reasons.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
