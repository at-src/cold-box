---
name: cb-adversary-in-the-middle-phishing-detection
skill_id: cb-adversary-in-the-middle-phishing-detection
journal_id: CB-SKL-125
description: Cold-box analyst playbook — Adversary In The Middle Phishing Detection.
  Detect and respond to Adversary-in-the-Middle (AiTM) phishing attacks that use reverse
  proxy kits like EvilProxy, Evilginx, and Tycoon 2FA to bypass MFA and steal session
  tokens.
domain: cold-box
subdomain: phishing-defense
tier: adjacent
case_profiles:
- threat_intel
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- aitm
- evilproxy
- evilginx
- phishing
- mfa-bypass
- session-hijacking
- reverse-proxy
- credential-theft
cold_box_version: 2
inspired_by: performing-adversary-in-the-middle-phishing-detection
---

# Adversary In The Middle Phishing Detection (cold-box)

> **Journal ID:** `CB-SKL-125` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-125`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-adversary-in-the-middle-phishing-detection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-adversary-in-the-middle-phishing-detection")` → note **`CB-SKL-125`**
2. `log_skill(case_id, journal_id="CB-SKL-125", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-125` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing adversary in the middle phishing detection
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

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
## {timestamp} — skill `CB-SKL-125` (`cb-adversary-in-the-middle-phishing-detection`)

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
Adversary-in-the-Middle (AiTM) phishing attacks use reverse-proxy infrastructure to sit between the victim and the legitimate authentication service, intercepting both credentials and session cookies in real time. This allows attackers to bypass multi-factor authentication (MFA). The most prevalent PhaaS kits in 2025 include Tycoon 2FA, Sneaky 2FA, EvilProxy, and Evilginx. Over 1 million PhaaS attacks were detected in January-February 2025 alone. These attacks have evolved from QR codes to HTML attachments and SVG files for link distribution.


## When to Use

- When conducting security assessments that involve performing adversary in the middle phishing detection
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites
- Azure AD / Entra ID Conditional Access policies
- SIEM with authentication log ingestion (Azure AD sign-in logs)
- Web proxy with SSL inspection and URL categorization
- Endpoint Detection and Response (EDR) solution
- FIDO2/phishing-resistant MFA capability

## Key Concepts

### How AiTM Works
1. Victim receives phishing email with link to attacker-controlled domain
2. Attacker domain runs reverse proxy that mirrors legitimate login page
3. Victim enters credentials on proxied page; credentials captured in transit
4. Reverse proxy forwards credentials to real authentication service
5. MFA challenge sent to victim; victim completes MFA on proxied page
6. Attacker captures session cookie returned by legitimate service
7. Attacker replays session cookie to access victim's account without MFA

### Major AiTM Kits (2025)
| Kit | Type | Primary Targets | Evasion |
|---|---|---|---|
| Tycoon 2FA | PhaaS | Microsoft 365, Google | CAPTCHA, Cloudflare turnstile |
| EvilProxy | PhaaS | Microsoft 365, Google, Okta | Random URLs, IP rotation |
| Evilginx | Open-source | Any web application | Custom phishlets |
| Sneaky 2FA | PhaaS | Microsoft 365 | Anti-bot checks |
| NakedPages | PhaaS | Multiple | Minimal infrastructure |

### Detection Indicators
- Authentication from unusual IP not matching user profile
- Session cookie reuse from different IP/device than authentication
- Login page served from non-Microsoft/non-Google infrastructure
- CDN requests to legitimate auth providers from phishing domains
- Impossible travel between authentication and session usage

## Workflow

### Step 1: Deploy Phishing-Resistant MFA
- Implement FIDO2 security keys or Windows Hello for Business for high-value accounts
- Configure Conditional Access to require phishing-resistant MFA for admins
- Enable certificate-based authentication where possible
- Disable SMS and voice MFA for privileged accounts
- AiTM cannot intercept FIDO2 because authentication is bound to origin domain

### Step 2: Configure Conditional Access Policies
- Require compliant/managed device for sensitive application access
- Block authentication from anonymous proxies and Tor exit nodes
- Enforce token binding to limit session cookie replay
- Configure continuous access evaluation (CAE) for real-time token revocation
- Implement sign-in risk policies that require re-authentication for risky sign-ins

### Step 3: Build AiTM Detection Rules
- Alert on sign-in followed by session from different IP within 10 minutes
- Detect authentication where proxy IP does not match user's expected location
- Monitor for impossible travel patterns in session usage
- Alert on inbox rules created immediately after authentication (common post-compromise)
- Detect new MFA method registration from suspicious sign-in

### Step 4: Monitor Web Proxy for AiTM Infrastructure
- Log and analyze DNS queries to newly registered domains
- Detect connections to known PhaaS infrastructure IPs
- Alert on authentication page backgrounds loaded from legitimate CDNs through proxy domains
- Monitor for SSL certificates issued to domains mimicking corporate login pages
- Block access to known EvilProxy/Evilginx infrastructure via threat intelligence

### Step 5: Implement Post-Compromise Detection
- Alert on mailbox forwarding rules created after suspicious authentication
- Detect OAuth app consent after AiTM sign-in
- Monitor for email sending patterns indicating BEC follow-up
- Alert on SharePoint/OneDrive mass download after session hijack
- Track lateral movement from compromised account

## Tools & Resources
- **Microsoft Entra ID Protection**: Risk-based Conditional Access
- **Azure AD Sign-in Logs**: Authentication event analysis
- **Okta ThreatInsight**: AiTM proxy detection at IdP level
- **Sekoia TDR**: AiTM campaign tracking and intelligence
- **Evilginx (defensive)**: Understanding attack mechanics for detection

## Validation
- Phishing-resistant MFA blocks AiTM session capture in test scenario
- Conditional Access denies session replay from different device/IP
- SIEM alerts fire on simulated AiTM sign-in patterns
- Web proxy blocks connections to known PhaaS infrastructure
- Post-compromise rules detect inbox rule creation after suspicious auth

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
