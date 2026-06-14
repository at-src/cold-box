---
name: cb-phishing-email-incident
skill_id: cb-phishing-email-incident
journal_id: CB-SKL-310
description: Cold-box analyst playbook — Phishing Email Incident. Investigates phishing
  email incidents from initial user report through header analysis, URL/attachment
  detonation, impacted user identification, and containment actions using SOC tools
  like Splunk, Microsoft Defender, and sandbox analysis p
domain: cold-box
subdomain: soc-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- soc
- phishing
- incident-response
- email-security
- splunk
- defender
- sandbox
cold_box_version: 2
inspired_by: investigating-phishing-email-incident
---

# Phishing Email Incident (cold-box)

> **Journal ID:** `CB-SKL-310` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-310`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-phishing-email-incident")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-phishing-email-incident")` → note **`CB-SKL-310`**
2. `log_skill(case_id, journal_id="CB-SKL-310", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-310` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- A user reports a suspicious email via the phishing report button or helpdesk ticket
- Email security gateway flags a message that bypassed initial filters
- Automated detection identifies credential harvesting URLs or malicious attachments
- A phishing campaign targeting the organization requires scope assessment

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-310] powershell per playbook step",
  "why": "Executing cb-phishing-email-incident \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-310] sort per playbook step",
  "why": "Executing cb-phishing-email-incident \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-310] file per playbook step",
  "why": "Executing cb-phishing-email-incident \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-310` (`cb-phishing-email-incident`)

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
- A user reports a suspicious email via the phishing report button or helpdesk ticket
- Email security gateway flags a message that bypassed initial filters
- Automated detection identifies credential harvesting URLs or malicious attachments
- A phishing campaign targeting the organization requires scope assessment

**Do not use** for spam or marketing emails without malicious intent — route those to email administration for filter tuning.

## Prerequisites

- Access to email gateway logs (Proofpoint, Mimecast, or Microsoft Defender for Office 365)
- Splunk or SIEM with email log ingestion (O365 Message Trace, Exchange tracking logs)
- Sandbox access (Any.Run, Joe Sandbox, or Hybrid Analysis) for URL/attachment detonation
- Microsoft Graph API or Exchange Admin Center for email search and purge operations
- URLScan.io and VirusTotal API keys

## Workflow

### Step 1: Extract and Analyze Email Headers

Obtain the full email headers (`.eml` file) from the reported message:

```python
import email
from email import policy

with open("phishing_sample.eml", "rb") as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

# Extract key headers
print(f"From: {msg['From']}")
print(f"Return-Path: {msg['Return-Path']}")
print(f"Reply-To: {msg['Reply-To']}")
print(f"Subject: {msg['Subject']}")
print(f"Message-ID: {msg['Message-ID']}")
print(f"X-Originating-IP: {msg['X-Originating-IP']}")

# Parse Received headers (bottom-up for true origin)
for header in reversed(msg.get_all('Received', [])):
    print(f"Received: {header[:120]}")

# Check authentication results
print(f"Authentication-Results: {msg['Authentication-Results']}")
print(f"DKIM-Signature: {msg.get('DKIM-Signature', 'NONE')[:80]}")
```

Key checks:
- **SPF**: Does `Return-Path` domain match sending IP? Look for `spf=pass` or `spf=fail`
- **DKIM**: Is the signature valid? `dkim=pass` confirms the email was not modified in transit
- **DMARC**: Does the `From` domain align with SPF/DKIM domains? `dmarc=fail` indicates spoofing

### Step 2: Analyze URLs and Attachments

**URL Analysis:**

```python
import requests

# Submit URL to URLScan.io
url_to_scan = "https://evil-login.example.com/office365"
response = requests.post(
    "https://urlscan.io/api/v1/scan/",
    headers={"API-Key": "YOUR_KEY", "Content-Type": "application/json"},
    json={"url": url_to_scan, "visibility": "unlisted"}
)
scan_id = response.json()["uuid"]
print(f"Scan URL: https://urlscan.io/result/{scan_id}/")

# Check VirusTotal for URL reputation
import vt
client = vt.Client("YOUR_VT_API_KEY")
url_id = vt.url_id(url_to_scan)
url_obj = client.get_object(f"/urls/{url_id}")
print(f"VT Score: {url_obj.last_analysis_stats}")
client.close()
```

**Attachment Analysis:**

```python
import hashlib

# Calculate file hashes
with open("attachment.docx", "rb") as f:
    content = f.read()
    md5 = hashlib.md5(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()

print(f"MD5: {md5}")
print(f"SHA256: {sha256}")

# Submit to MalwareBazaar for lookup
response = requests.post(
    "https://mb-api.abuse.ch/api/v1/",
    data={"query": "get_info", "hash": sha256}
)
print(response.json()["query_status"])
```

Submit to sandbox (Any.Run or Joe Sandbox) for dynamic analysis of macros, PowerShell execution, and C2 callbacks.

### Step 3: Determine Campaign Scope

Search for all recipients of the same phishing email in Splunk:

```spl
index=email sourcetype="o365:messageTrace"
(SenderAddress="attacker@evil-domain.com" OR Subject="Urgent: Password Reset Required"
 OR MessageId="<phishing-message-id@evil.com>")
earliest=-7d
| stats count by RecipientAddress, DeliveryStatus, MessageTraceId
| sort - count
```

Alternatively, use Microsoft Graph API:

```python
import requests

headers = {"Authorization": f"Bearer {access_token}"}
params = {
    "$filter": f"subject eq 'Urgent: Password Reset Required' and "
               f"receivedDateTime ge 2024-03-14T00:00:00Z",
    "$select": "sender,toRecipients,subject,receivedDateTime",
    "$top": 100
}
response = requests.get(
    "https://graph.microsoft.com/v1.0/users/admin@company.com/messages",
    headers=headers, params=params
)
messages = response.json()["value"]
print(f"Found {len(messages)} matching messages")
```

### Step 4: Identify Impacted Users (Who Clicked)

Check proxy/web logs for users who visited the phishing URL:

```spl
index=proxy dest="evil-login.example.com" earliest=-7d
| stats count, values(action) AS actions, latest(_time) AS last_access
  by src_ip, user
| lookup asset_lookup_by_cidr ip AS src_ip OUTPUT owner, category
| sort - count
| table user, src_ip, owner, actions, count, last_access
```

Check if credentials were submitted (POST requests to phishing domain):

```spl
index=proxy dest="evil-login.example.com" http_method=POST earliest=-7d
| stats count by src_ip, user, url, status
```

### Step 5: Containment Actions

**Purge emails from all mailboxes:**

```powershell
# Microsoft 365 Compliance Search and Purge
New-ComplianceSearch -Name "Phishing_Purge_2024_0315" `
    -ExchangeLocation All `
    -ContentMatchQuery '(From:attacker@evil-domain.com) AND (Subject:"Urgent: Password Reset Required")'

Start-ComplianceSearch -Identity "Phishing_Purge_2024_0315"

# After search completes, execute purge
New-ComplianceSearchAction -SearchName "Phishing_Purge_2024_0315" -Purge -PurgeType SoftDelete
```

**Block indicators:**
- Add sender domain to email gateway block list
- Add phishing URL domain to web proxy block list
- Add attachment hash to endpoint detection block list
- Create DNS sinkhole entry for phishing domain

**Reset compromised credentials:**

```powershell
# Force password reset for impacted users
$impactedUsers = @("user1@company.com", "user2@company.com")
foreach ($user in $impactedUsers) {
    Set-MsolUserPassword -UserPrincipalName $user -ForceChangePassword $true
    Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -ObjectId $user).ObjectId
}
```

### Step 6: Document and Report

Create incident report with full timeline, IOCs, impacted users, and remediation actions taken.

```spl
| makeresults
| eval incident_id="PHI-2024-0315",
       reported_time="2024-03-15 09:12:00",
       sender="attacker@evil-domain[.]com",
       subject="Urgent: Password Reset Required",
       url="hxxps://evil-login[.]example[.]com/office365",
       recipients_count=47,
       clicked_count=5,
       credentials_submitted=2,
       emails_purged=47,
       passwords_reset=2,
       domains_blocked=1,
       disposition="True Positive - Credential Phishing Campaign"
| table incident_id, reported_time, sender, subject, url, recipients_count,
        clicked_count, credentials_submitted, emails_purged, passwords_reset, disposition
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **SPF (Sender Policy Framework)** | DNS TXT record specifying which mail servers are authorized to send on behalf of a domain |
| **DKIM** | DomainKeys Identified Mail — cryptographic signature proving email content was not altered in transit |
| **DMARC** | Domain-based Message Authentication, Reporting and Conformance — policy combining SPF and DKIM alignment |
| **Credential Harvesting** | Phishing technique using fake login pages to capture username/password combinations |
| **Business Email Compromise (BEC)** | Social engineering attack using compromised or spoofed executive email for financial fraud |
| **Message Trace** | O365/Exchange log showing email routing, delivery status, and filtering actions for forensic analysis |

## Tools & Systems

- **Microsoft Defender for Office 365**: Email security platform with Safe Links, Safe Attachments, and Threat Explorer for investigation
- **URLScan.io**: Free URL analysis service capturing screenshots, DOM, cookies, and network requests
- **Any.Run**: Interactive sandbox for detonating malicious files and URLs with real-time behavior analysis
- **Proofpoint TAP**: Targeted Attack Protection dashboard showing clicked URLs and delivered threats per user
- **PhishTool**: Dedicated phishing email analysis platform automating header parsing and IOC extraction

## Common Scenarios

- **Credential Phishing**: Fake O365 login page — check proxy for POST requests, force password resets for submitters
- **Macro-Enabled Document**: Word doc with VBA macro — sandbox shows PowerShell download cradle, check endpoints for execution
- **QR Code Phishing (Quishing)**: Email contains QR code linking to credential harvester — decode QR, submit URL to sandbox
- **Thread Hijacking**: Attacker uses compromised mailbox to reply in existing threads — check for impossible travel or new inbox rules
- **Voicemail Phishing**: Fake voicemail notification with HTML attachment — analyze attachment for redirect chains

## Output Format

```
PHISHING INCIDENT REPORT — PHI-2024-0315
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Reported:     2024-03-15 09:12 UTC by jsmith (Finance)
Sender:       attacker@evil-domain[.]com (SPF: FAIL, DKIM: NONE, DMARC: FAIL)
Subject:      Urgent: Password Reset Required
Payload:      Credential harvesting URL

IOCs:
  URL:        hxxps://evil-login[.]example[.]com/office365
  Domain:     evil-login[.]example[.]com (registered 2024-03-14, Namecheap)
  IP:         185.234.xx.xx (VT: 12/90 malicious)

Scope:
  Recipients: 47 users across Finance and HR departments
  Clicked:    5 users visited phishing URL
  Submitted:  2 users entered credentials (confirmed via POST in proxy logs)

Containment:
  [DONE] 47 emails purged via Compliance Search
  [DONE] Domain blocked on proxy and DNS sinkhole
  [DONE] 2 user passwords reset, sessions revoked
  [DONE] MFA enforced for both compromised accounts
  [DONE] Inbox rules audited — no forwarding rules found

Status:       RESOLVED — No evidence of lateral movement post-compromise
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
