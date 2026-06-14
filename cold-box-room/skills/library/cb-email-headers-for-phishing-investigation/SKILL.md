---
name: cb-email-headers-for-phishing-investigation
skill_id: cb-email-headers-for-phishing-investigation
journal_id: CB-SKL-038
description: Cold-box analyst playbook — Email Headers For Phishing Investigation.
  Parse and analyze email headers to trace the origin of phishing emails, verify sender
  authenticity, and identify spoofing through SPF, DKIM, and DMARC validation.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- forensics
- email-analysis
- phishing
- spf
- dkim
- dmarc
- header-analysis
cold_box_version: 2
inspired_by: analyzing-email-headers-for-phishing-investigation
---

# Email Headers For Phishing Investigation (cold-box)

> **Journal ID:** `CB-SKL-038` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-038`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-email-headers-for-phishing-investigation")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-email-headers-for-phishing-investigation")` → note **`CB-SKL-038`**
2. `log_skill(case_id, journal_id="CB-SKL-038", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-038` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating a suspected phishing email to determine its true origin
- For verifying sender authenticity and detecting email spoofing
- During incident response when a user has clicked a phishing link
- When tracing the delivery path and relay servers of a suspicious email
- For validating SPF, DKIM, and DMARC alignment to identify forgery

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `grep` | `SIFT-010` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-038] grep per playbook step",
  "why": "Executing cb-email-headers-for-phishing-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-038] file per playbook step",
  "why": "Executing cb-email-headers-for-phishing-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-038` (`cb-email-headers-for-phishing-investigation`)

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
- When investigating a suspected phishing email to determine its true origin
- For verifying sender authenticity and detecting email spoofing
- During incident response when a user has clicked a phishing link
- When tracing the delivery path and relay servers of a suspicious email
- For validating SPF, DKIM, and DMARC alignment to identify forgery

## Prerequisites
- Raw email headers from the suspicious message (EML or MSG format)
- Understanding of SMTP protocol and email header fields
- Access to DNS lookup tools (dig, nslookup) for SPF/DKIM/DMARC verification
- Email header analysis tools (MHA, emailheaders.net concepts)
- Python with email parsing libraries for automated analysis
- Access to threat intelligence platforms for IP/domain reputation

## Workflow

### Step 1: Extract Raw Email Headers

```bash
# Export from Outlook: Open email > File > Properties > Internet Headers
# Export from Gmail: Open email > Three dots > Show original
# Export from Thunderbird: View > Message Source

# If working with EML file from forensic image
cp /mnt/evidence/Users/suspect/AppData/Local/Microsoft/Outlook/phishing_email.eml \
   /cases/case-2024-001/email/

# If working with PST file, extract individual messages
pip install pypff
python3 << 'PYEOF'
import pypff

pst = pypff.file()
pst.open("/cases/case-2024-001/email/outlook.pst")
root = pst.get_root_folder()

def extract_messages(folder, path=""):
    for i in range(folder.get_number_of_sub_messages()):
        msg = folder.get_sub_message(i)
        headers = msg.get_transport_headers()
        subject = msg.get_subject()
        if headers:
            filename = f"/cases/case-2024-001/email/msg_{i}_{subject[:30]}.txt"
            with open(filename, 'w') as f:
                f.write(headers)
    for i in range(folder.get_number_of_sub_folders()):
        extract_messages(folder.get_sub_folder(i))

extract_messages(root)
PYEOF
```

### Step 2: Parse the Email Header Chain

```bash
# Parse headers using Python email library
python3 << 'PYEOF'
import email
from email import policy

with open('/cases/case-2024-001/email/phishing_email.eml', 'r') as f:
    msg = email.message_from_file(f, policy=policy.default)

print("=== KEY HEADER FIELDS ===")
print(f"From:          {msg['From']}")
print(f"To:            {msg['To']}")
print(f"Subject:       {msg['Subject']}")
print(f"Date:          {msg['Date']}")
print(f"Message-ID:    {msg['Message-ID']}")
print(f"Reply-To:      {msg['Reply-To']}")
print(f"Return-Path:   {msg['Return-Path']}")
print(f"X-Mailer:      {msg['X-Mailer']}")
print(f"X-Originating-IP: {msg['X-Originating-IP']}")

print("\n=== RECEIVED HEADERS (bottom-up = chronological) ===")
received_headers = msg.get_all('Received')
if received_headers:
    for i, header in enumerate(reversed(received_headers)):
        print(f"\nHop {i+1}: {header.strip()}")

print("\n=== AUTHENTICATION RESULTS ===")
auth_results = msg.get_all('Authentication-Results')
if auth_results:
    for result in auth_results:
        print(result)

print(f"\nARC-Authentication-Results: {msg.get('ARC-Authentication-Results', 'Not present')}")
print(f"Received-SPF: {msg.get('Received-SPF', 'Not present')}")
print(f"DKIM-Signature: {msg.get('DKIM-Signature', 'Not present')}")
PYEOF
```

### Step 3: Validate SPF, DKIM, and DMARC Records

```bash
# Extract the envelope sender domain
SENDER_DOMAIN="example-corp.com"

# Check SPF record
dig TXT $SENDER_DOMAIN +short | grep "v=spf1"
# Example: "v=spf1 include:_spf.google.com include:sendgrid.net ~all"

# Check DKIM record (selector from DKIM-Signature header, e.g., "s=selector1")
DKIM_SELECTOR="selector1"
dig TXT ${DKIM_SELECTOR}._domainkey.${SENDER_DOMAIN} +short

# Check DMARC record
dig TXT _dmarc.${SENDER_DOMAIN} +short
# Example: "v=DMARC1; p=reject; rua=mailto:dmarc@example-corp.com; pct=100"

# Verify the sending IP against SPF
# Extract IP from first Received header
SENDING_IP="203.0.113.45"

# Manual SPF check using python
python3 << 'PYEOF'
import spf  # pip install pyspf

result, explanation = spf.check2(
    i='203.0.113.45',
    s='sender@example-corp.com',
    h='mail.example-corp.com'
)
print(f"SPF Result: {result}")
print(f"Explanation: {explanation}")
# Results: pass, fail, softfail, neutral, none, temperror, permerror
PYEOF

# Check if sending IP is in known malicious IP lists
# Query AbuseIPDB or VirusTotal
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=${SENDING_IP}" \
   -H "Key: YOUR_API_KEY" -H "Accept: application/json" | python3 -m json.tool
```

### Step 4: Analyze Sender Domain and Infrastructure

```bash
# WHOIS lookup on sender domain
whois $SENDER_DOMAIN | grep -iE '(registrar|creation|expiration|registrant|nameserver)'

# Check domain age (recently registered domains are suspicious)
# DNS record investigation
dig A $SENDER_DOMAIN +short
dig MX $SENDER_DOMAIN +short
dig NS $SENDER_DOMAIN +short

# Reverse DNS on sending IP
dig -x $SENDING_IP +short

# Check for lookalike/typosquatting domains
# Compare with legitimate domain using visual similarity
python3 << 'PYEOF'
import Levenshtein  # pip install python-Levenshtein

legitimate = "microsoft.com"
suspicious = "micr0soft.com"

distance = Levenshtein.distance(legitimate, suspicious)
ratio = Levenshtein.ratio(legitimate, suspicious)
print(f"Edit distance: {distance}")
print(f"Similarity ratio: {ratio:.2%}")
if ratio > 0.8:
    print("WARNING: Likely typosquatting/lookalike domain!")
PYEOF

# Check domain reputation on VirusTotal
curl -s "https://www.virustotal.com/api/v3/domains/${SENDER_DOMAIN}" \
   -H "x-apikey: YOUR_VT_API_KEY" | python3 -m json.tool

# Check if the Reply-To differs from From (common phishing indicator)
python3 -c "
import email
with open('/cases/case-2024-001/email/phishing_email.eml') as f:
    msg = email.message_from_file(f)
from_addr = email.utils.parseaddr(msg['From'])[1]
reply_to = email.utils.parseaddr(msg.get('Reply-To', msg['From']))[1]
if from_addr != reply_to:
    print(f'WARNING: From ({from_addr}) != Reply-To ({reply_to})')
else:
    print('From and Reply-To match')
"
```

### Step 5: Examine Email Body and Attachments

```bash
# Extract URLs from email body
python3 << 'PYEOF'
import email
import re
from email import policy

with open('/cases/case-2024-001/email/phishing_email.eml', 'r') as f:
    msg = email.message_from_file(f, policy=policy.default)

body = msg.get_body(preferencelist=('html', 'plain'))
if body:
    content = body.get_content()
    urls = re.findall(r'https?://[^\s<>"\']+', content)
    print("=== URLs FOUND IN EMAIL BODY ===")
    for url in set(urls):
        print(f"  {url}")

    # Check for URL obfuscation (display text != href)
    href_pattern = re.findall(r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', content, re.DOTALL)
    print("\n=== HYPERLINK ANALYSIS ===")
    for href, text in href_pattern:
        display_url = re.findall(r'https?://[^\s<]+', text)
        if display_url and display_url[0] != href:
            print(f"  MISMATCH: Display='{display_url[0]}' -> Actual='{href}'")

# Extract and hash attachments
print("\n=== ATTACHMENTS ===")
for part in msg.walk():
    if part.get_content_disposition() == 'attachment':
        filename = part.get_filename()
        content = part.get_payload(decode=True)
        import hashlib
        sha256 = hashlib.sha256(content).hexdigest()
        print(f"  File: {filename}, Size: {len(content)}, SHA-256: {sha256}")
        with open(f'/cases/case-2024-001/email/attachments/{filename}', 'wb') as af:
            af.write(content)
PYEOF

# Submit attachment hashes to VirusTotal
# Submit URLs to URLhaus or PhishTank for reputation check
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| SPF (Sender Policy Framework) | DNS record specifying authorized mail servers for a domain |
| DKIM (DomainKeys Identified Mail) | Cryptographic signature verifying email content integrity |
| DMARC | Policy framework combining SPF and DKIM for sender authentication |
| Received headers | Server-added headers showing each hop in the delivery chain (read bottom to top) |
| Return-Path | Envelope sender address used for bounce messages; may differ from From |
| Message-ID | Unique identifier assigned by the originating mail server |
| X-Originating-IP | Original sender IP address (added by some mail services) |
| Header forgery | Attackers can forge From, Reply-To, and other headers but not Received chains |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| MXToolbox | Online email header analyzer and DNS lookup |
| dig/nslookup | DNS record queries for SPF, DKIM, DMARC verification |
| pyspf | Python SPF record validation library |
| dkimpy | Python DKIM signature verification library |
| PhishTool | Specialized phishing email analysis platform |
| VirusTotal | URL and file reputation checking service |
| AbuseIPDB | IP address reputation database |
| whois | Domain registration information lookup |

## Common Scenarios

**Scenario 1: CEO Fraud / Business Email Compromise**
The email claims to be from the CEO but Reply-To points to a Gmail address, SPF fails because the sending IP is not authorized for the spoofed domain, DKIM is missing, and the From domain is a lookalike (ceo-company.com vs company.com).

**Scenario 2: Credential Harvesting Phishing**
Email contains a link that displays "login.microsoft.com" but href points to a lookalike domain, the attachment is an HTML file containing a fake login page with credential exfiltration JavaScript, the sending domain was registered 3 days ago.

**Scenario 3: Malware Delivery via Attachment**
Email with an Office document attachment containing macros, the sender domain passes SPF but the account was compromised, DKIM signature is valid (sent from legitimate infrastructure), attachment SHA-256 matches known malware on VirusTotal.

**Scenario 4: Spear Phishing with Legitimate Service**
Attacker uses a legitimate email marketing service to send phishing, SPF and DKIM pass because the service is authorized, the phishing is in the content not the infrastructure, requires URL and content analysis rather than header authentication checks.

## Output Format

```
Email Header Analysis Report:
  Subject:     "Urgent: Invoice Payment Required"
  From:        accounting@examp1e-corp.com (SPOOFED)
  Reply-To:    payments.urgent@gmail.com (MISMATCH)
  Return-Path: <bounce@mail-server.xyz>
  Date:        2024-01-15 09:23:45 UTC

  Delivery Path (4 hops):
    Hop 1: mail-server.xyz [203.0.113.45] -> relay1.isp.com
    Hop 2: relay1.isp.com -> mx.target-company.com
    Hop 3: mx.target-company.com -> internal-filter.target.com
    Hop 4: internal-filter.target.com -> mailbox

  Authentication:
    SPF:    FAIL (203.0.113.45 not authorized for examp1e-corp.com)
    DKIM:   NONE (no signature present)
    DMARC:  FAIL (p=none, no enforcement)

  Indicators of Phishing:
    - Lookalike domain (examp1e-corp.com vs example-corp.com, 96% similar)
    - From/Reply-To mismatch
    - Domain registered 2 days before email sent
    - URL in body points to credential harvesting page
    - Attachment: invoice.xlsm (SHA-256: a3f2...) - Known malware on VT

  Risk Level: HIGH
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
