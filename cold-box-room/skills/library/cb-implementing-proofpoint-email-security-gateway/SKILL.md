---
name: cb-implementing-proofpoint-email-security-gateway
skill_id: cb-implementing-proofpoint-email-security-gateway
journal_id: CB-SKL-277
description: Cold-box analyst playbook — Implementing Proofpoint Email Security Gateway.
  Deploy and configure Proofpoint Email Protection as a secure email gateway to detect
  and block phishing, malware, BEC, and spam before messages reach user inboxes.
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
- email-security
- proofpoint
- secure-email-gateway
- phishing
- anti-spam
- anti-malware
- bec
- email-filtering
cold_box_version: 2
inspired_by: implementing-proofpoint-email-security-gateway
---

# Implementing Proofpoint Email Security Gateway (cold-box)

> **Journal ID:** `CB-SKL-277` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-277`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-proofpoint-email-security-gateway")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-proofpoint-email-security-gateway")` → note **`CB-SKL-277`**
2. `log_skill(case_id, journal_id="CB-SKL-277", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-277` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing proofpoint email security gateway capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

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
## {timestamp} — skill `CB-SKL-277` (`cb-implementing-proofpoint-email-security-gateway`)

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
Proofpoint Email Protection is a cloud-native secure email gateway (SEG) that acts as a security checkpoint where all inbound and outbound mail traffic routes through the gateway before reaching user inboxes. It combines signature-based detection for known malware, machine learning algorithms for emerging threats, real-time threat intelligence feeds, URL rewriting with time-of-click sandboxing, and behavioral analysis for BEC detection. Proofpoint processes over 2.8 billion emails daily and blocks over 1 million extortion attempts per day.


## When to Use

- When deploying or configuring implementing proofpoint email security gateway capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites
- Proofpoint Email Protection license (PPS on-premises or Proofpoint on Demand cloud)
- Administrative access to DNS management for MX record changes
- Microsoft 365 or Google Workspace email environment
- Understanding of mail flow architecture and SPF/DKIM/DMARC
- Network firewall rules permitting Proofpoint IP ranges

## Key Concepts

### Deployment Models
1. **MX-Based Gateway (Traditional SEG)**: All mail routes through Proofpoint via MX record changes; intercepts threats before delivery
2. **API-Based Integration**: Connects directly to Microsoft 365 or Google Workspace via API; no MX changes required; can be operational within 48 hours
3. **Hybrid Deployment**: Combines gateway and API for layered protection

### Core Detection Technologies
- **Impostor Classifier**: ML model detecting BEC/impersonation with no malicious URLs or attachments
- **URL Defense**: Rewrites URLs and performs real-time sandboxing at time of click
- **Attachment Defense**: Sandboxes suspicious attachments in virtual environments
- **Nexus Threat Graph**: Cross-customer threat intelligence correlation engine
- **Supplier Threat Detection**: Identifies compromised vendor email accounts

### Protection Layers
| Layer | Technology | Threat Type |
|---|---|---|
| Connection | IP reputation, rate limiting | Spam botnets |
| Authentication | SPF, DKIM, DMARC enforcement | Spoofing |
| Content | ML classifiers, NLP analysis | BEC, phishing |
| URL | Rewriting + time-of-click sandbox | Credential theft |
| Attachment | Static + dynamic sandboxing | Malware, ransomware |
| Post-delivery | TRAP (auto-retraction) | Weaponized after delivery |

## Workflow

### Step 1: Plan Mail Flow Architecture
- Document current MX records and mail flow path
- Identify all legitimate sending sources (marketing platforms, CRM, ticketing systems)
- Map inbound connectors and transport rules in Microsoft 365 or Google Workspace
- Plan IP allowlisting for Proofpoint egress IPs on receiving infrastructure
- Configure SPF record to include Proofpoint: `v=spf1 include:spf.protection.outlook.com include:spf-a.proofpoint.com -all`

### Step 2: Configure Proofpoint Policies
- Create organizational units matching business structure
- Define inbound mail policies: anti-spam, anti-virus, impostor detection
- Configure Smart Search quarantine with end-user digest notifications
- Set up Proofpoint Encryption for sensitive outbound messages
- Enable Targeted Attack Protection (TAP) for URL and attachment sandboxing

### Step 3: Deploy Email Authentication
- Configure DKIM signing through Proofpoint for outbound messages
- Set DMARC policy to monitor mode initially: `v=DMARC1; p=none; rua=mailto:dmarc@company.com`
- Enable inbound DMARC enforcement to reject spoofed messages
- Configure anti-spoofing rules for executive impersonation protection

### Step 4: Enable Advanced Threat Protection
- Activate URL Defense with rewriting enabled for all inbound messages
- Configure Attachment Defense sandbox policies (safe attachment mode)
- Enable Threat Response Auto-Pull (TRAP) for post-delivery remediation
- Set up TAP Dashboard alerts for targeted attack campaigns
- Configure Supplier Risk monitoring for vendor email compromise

### Step 5: Migrate MX Records
- Lower MX record TTL to 300 seconds 48 hours before cutover
- Update MX records to point to Proofpoint: `company-com.mail.protection.proofpoint.com`
- Configure connector restrictions in Microsoft 365 to accept mail only from Proofpoint IPs
- Monitor mail flow through Proofpoint Message Trace for 48-72 hours
- Verify no legitimate mail is being blocked or delayed

### Step 6: Tune and Optimize
- Review quarantine and false positive/negative rates weekly for first month
- Adjust spam thresholds based on organizational tolerance
- Add approved senders and safe lists for legitimate bulk mail
- Configure data loss prevention (DLP) rules for outbound sensitive content
- Enable email warning banners for external sender identification

## Tools & Resources
- **Proofpoint TAP Dashboard**: Real-time threat visibility and campaign tracking
- **Proofpoint TRAP**: Automated post-delivery email retraction
- **Proofpoint SER (Spam/End-user Release)**: Self-service quarantine management
- **Proofpoint Closed-Loop Email Analysis (CLEAR)**: Phishing report button integration
- **MX Toolbox**: DNS record verification and mail flow testing

## Validation
- All inbound email routes through Proofpoint (verify MX records and message headers)
- TAP Dashboard shows threat detections and blocked campaigns
- URL Defense rewrites links in test messages and sandboxes at click time
- Attachment Defense detonates test malware samples in sandbox
- TRAP successfully retracts test phishing message from inboxes post-delivery
- False positive rate below 0.1% after initial tuning period
- DMARC/SPF/DKIM authentication passes for all legitimate outbound mail

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
