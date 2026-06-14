---
name: cb-phishing-incident-response
skill_id: cb-phishing-incident-response
journal_id: CB-SKL-099
description: Cold-box analyst playbook — Phishing Incident Response. Responds to phishing
  incidents by analyzing reported emails, extracting indicators, assessing credential
  compromise, quarantining malicious messages across the organization, and remediating
  affected accounts. Covers email header analysis, U
domain: cold-box
subdomain: incident-response
tier: core
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- phishing-response
- email-security
- credential-compromise
- email-header-analysis
- mailbox-remediation
cold_box_version: 2
inspired_by: conducting-phishing-incident-response
---

# Phishing Incident Response (cold-box)

> **Journal ID:** `CB-SKL-099` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-099`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-phishing-incident-response")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-phishing-incident-response")` → note **`CB-SKL-099`**
2. `log_skill(case_id, journal_id="CB-SKL-099", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-099` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- A user reports receiving a suspicious email via the phishing report button or abuse mailbox
- Email gateway detects a malicious email that bypassed initial filtering
- Threat intelligence indicates an active phishing campaign targeting the organization
- A user confirms they clicked a link or opened an attachment from a suspicious email
- Credentials have been entered on a suspected phishing page

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `find` | `SIFT-009` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-099] powershell per playbook step",
  "why": "Executing cb-phishing-incident-response \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-099] find per playbook step",
  "why": "Executing cb-phishing-incident-response \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-099] file per playbook step",
  "why": "Executing cb-phishing-incident-response \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-099` (`cb-phishing-incident-response`)

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

- A user reports receiving a suspicious email via the phishing report button or abuse mailbox
- Email gateway detects a malicious email that bypassed initial filtering
- Threat intelligence indicates an active phishing campaign targeting the organization
- A user confirms they clicked a link or opened an attachment from a suspicious email
- Credentials have been entered on a suspected phishing page

**Do not use** for business email compromise (BEC) involving compromised internal accounts; use BEC response procedures which focus on account takeover investigation.

## Prerequisites

- Email security gateway with message trace and quarantine capabilities (Microsoft Defender for Office 365, Proofpoint, Mimecast)
- Microsoft 365 admin access or Google Workspace admin for mailbox search and purge
- Malware sandbox for attachment and URL analysis (ANY.RUN, Joe Sandbox, Hybrid Analysis)
- Email header analysis tools (MXToolbox Header Analyzer, Google Admin Toolbox)
- Identity provider access for account remediation (Azure AD, Okta, Duo)
- Phishing report intake process (dedicated mailbox or integrated report button)

## Workflow

### Step 1: Receive and Triage the Phishing Report

Evaluate the reported email to determine if it is malicious:

- Extract the email as an .EML or .MSG file (preserves headers)
- Analyze email headers to determine the true sender, relay path, and authentication results

```
Email Header Analysis Checklist:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Return-Path:     billing@spoofed-domain[.]com
From:            "IT Support" <support@corp-lookalike[.]com>
Reply-To:        attacker@gmail[.]com (different from From)
SPF:             FAIL (sender IP not authorized for domain)
DKIM:            FAIL (signature invalid)
DMARC:           FAIL (policy: none - no enforcement)
Received:        from mail.attacker-infra[.]net [45.33.x.x]
X-Originating-IP: 45.33.x.x
Message-ID:      <random@attacker-infra.net>
```

Classification criteria:
- **Confirmed Phishing**: Malicious URL/attachment, spoofed sender, credential harvesting page
- **Suspicious**: Anomalous headers but no confirmed malicious content
- **Spam/Marketing**: Unwanted but not malicious
- **Legitimate**: Not a phishing email (false report)

### Step 2: Analyze Malicious Content

Examine URLs and attachments in a safe environment:

**URL Analysis:**
- Check URL against VirusTotal, URLscan.io, and Google Safe Browsing
- Open URL in a sandbox browser to capture the landing page
- Check if the URL redirects to a credential harvesting page
- Identify the phishing kit type (Microsoft 365 login clone, Okta clone, generic)
- Determine if the phishing page is still active

**Attachment Analysis:**
- Calculate file hash (SHA-256) and check against VirusTotal
- Detonate in sandbox (ANY.RUN, Joe Sandbox)
- Analyze document for macros (olevba for Office files)
- Check for embedded exploits (CVE exploitation in document parsers)

### Step 3: Determine Scope of Impact

Identify all recipients and assess who interacted with the phishing email:

```
Scope Assessment:
━━━━━━━━━━━━━━━━
Total Recipients:     47 users
Delivered to Inbox:   38 users (9 caught by email gateway)
Opened Email:         24 users (email tracking pixel data)
Clicked Link:         8 users (proxy/firewall logs)
Entered Credentials:  3 users (phishing page submitted form data)
Opened Attachment:    2 users (EDR process execution telemetry)
```

Search methods:
- Microsoft 365: Use Threat Explorer or Content Search to find all instances of the email
- Google Workspace: Use Admin Console > Investigation tool for message search
- Proxy logs: Search for connections to the phishing URL from internal IPs
- EDR: Search for attachment file hash execution across all endpoints

### Step 4: Contain the Threat

Execute containment actions based on impact assessment:

**Email Containment:**
- Purge the phishing email from all mailboxes using Microsoft 365 Content Search and Purge or Google Workspace Admin delete
- Block the sender domain at the email gateway
- Add the phishing URL to the web proxy blocklist
- Add attachment hash to email gateway and EDR blocklists

**Account Containment (for users who entered credentials):**
- Force password reset immediately
- Revoke all active sessions and OAuth tokens
- Enable or re-verify MFA enrollment
- Review mailbox rules for attacker-created forwarding rules
- Check for unauthorized OAuth application grants
- Review recent sign-in activity for suspicious locations

```powershell
# Microsoft 365: Revoke sessions and reset password
Connect-AzureAD
Revoke-AzureADUserAllRefreshToken -ObjectId "user@corp.com"
Set-AzureADUserPassword -ObjectId "user@corp.com" -ForceChangePasswordNextLogin $true

# Check for mailbox forwarding rules
Get-InboxRule -Mailbox "user@corp.com" | Where-Object {$_.ForwardTo -or $_.RedirectTo}

# Remove suspicious forwarding rules
Remove-InboxRule -Mailbox "user@corp.com" -Identity "Rule Name"
```

### Step 5: Eradicate and Recover

Remove all traces of the phishing attack:

- Confirm email purge completed successfully across all mailboxes
- Verify compromised accounts have been secured (password changed, sessions revoked, MFA verified)
- Remove any malware installed via phishing attachments from affected endpoints
- Monitor compromised accounts for 72 hours for signs of continued unauthorized access
- Check for data exfiltration from compromised accounts during the exposure window

### Step 6: Post-Incident Actions

Strengthen defenses against similar phishing attacks:

- Report the phishing URL to Google Safe Browsing and Microsoft SmartScreen
- Submit the phishing domain for takedown via the domain registrar abuse contact
- Update email gateway filtering rules based on observed evasion techniques
- Send targeted security awareness notification to affected users
- Update phishing simulation program to include the observed technique

## Key Concepts

| Term | Definition |
|------|------------|
| **Spear Phishing** | Targeted phishing attack crafted for a specific individual or organization using personalized content |
| **Credential Harvesting** | Phishing technique that mimics a legitimate login page to capture usernames and passwords |
| **SPF (Sender Policy Framework)** | Email authentication protocol that specifies which mail servers are authorized to send email for a domain |
| **DKIM (DomainKeys Identified Mail)** | Email authentication method using cryptographic signatures to verify that an email was not altered in transit |
| **DMARC** | Policy framework that uses SPF and DKIM to determine email authenticity and instructs receivers on handling failures |
| **OAuth Consent Phishing** | Attack that tricks users into granting malicious OAuth applications access to their email and data |
| **Email Header** | Metadata embedded in every email containing routing, authentication, and sender information used for forensic analysis |

## Tools & Systems

- **Microsoft Defender for Office 365**: Email threat protection with Threat Explorer for investigation and automated purge
- **Proofpoint TAP (Targeted Attack Protection)**: Email security platform with URL rewriting and attachment sandboxing
- **URLscan.io**: Online service that scans URLs and captures screenshots of phishing pages for evidence
- **PhishTool**: Phishing analysis platform that automates header analysis, URL inspection, and IOC extraction
- **GoPhish**: Open-source phishing simulation platform for security awareness testing

## Common Scenarios

### Scenario: Microsoft 365 Credential Phishing via QR Code

**Context**: Users report an email claiming to be from IT requiring MFA re-enrollment. The email contains a QR code that links to a convincing Microsoft 365 login page clone hosted on a compromised WordPress site.

**Approach**:
1. Scan the QR code in a sandbox to extract the URL
2. Analyze the phishing page: captures credentials and MFA tokens (adversary-in-the-middle attack)
3. Search email gateway for all recipients using message subject and sender as search criteria
4. Cross-reference with proxy logs to identify users who visited the phishing URL
5. Force password reset and revoke sessions for all users who visited the URL
6. Purge the email from all mailboxes and block the sender domain
7. Notify users about the specific campaign with visual examples of the phishing email

**Pitfalls**:
- Not checking for adversary-in-the-middle (AiTM) capability that captures session tokens even with MFA
- Only resetting passwords without revoking active sessions (attacker retains access via stolen session cookies)
- Not searching for mailbox forwarding rules created by the attacker after compromising an account
- Missing QR code phishing (quishing) because URL scanning tools cannot decode QR code images

## Output Format

```
PHISHING INCIDENT RESPONSE REPORT
===================================
Incident:          INC-2025-1602
Date Reported:     2025-11-16T09:15:00Z
Reported By:       jdoe@corp.example.com
Classification:    Credential Phishing (AiTM)

EMAIL ANALYSIS
Subject:       "Action Required: MFA Re-enrollment"
Sender:        it-support@corp-security[.]com (spoofed)
SPF:           FAIL | DKIM: FAIL | DMARC: FAIL
Phishing URL:  hxxps://compromised-site[.]com/ms365/login
Phishing Type: Microsoft 365 AiTM credential harvester

IMPACT ASSESSMENT
Recipients:        47
Clicked Link:      8
Credentials Entered: 3 (confirmed via proxy POST data)

CONTAINMENT ACTIONS
[x] Email purged from all 47 mailboxes
[x] Phishing domain blocked at web proxy
[x] Sender domain blocked at email gateway
[x] 3 compromised accounts: passwords reset, sessions revoked
[x] Mailbox forwarding rules reviewed (1 malicious rule removed)
[x] OAuth app grants reviewed (no unauthorized grants found)

IOCs EXTRACTED
Domain:  corp-security[.]com
URL:     hxxps://compromised-site[.]com/ms365/login
IP:      104.21.x.x (Cloudflare-hosted)
Sender:  it-support@corp-security[.]com

RECOMMENDATIONS
1. Implement DMARC enforcement (p=reject) for corp domain
2. Deploy QR code scanning in email gateway
3. Send targeted awareness notification to all 47 recipients
4. Request domain takedown via registrar abuse contact
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
