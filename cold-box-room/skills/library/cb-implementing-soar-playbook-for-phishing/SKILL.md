---
name: cb-implementing-soar-playbook-for-phishing
skill_id: cb-implementing-soar-playbook-for-phishing
journal_id: CB-SKL-283
description: Cold-box analyst playbook — Implementing Soar Playbook For Phishing.
  Automate phishing incident response using Splunk SOAR REST API to create containers,
  add artifacts, and trigger playbooks
domain: cold-box
subdomain: security-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- soar
- splunk-phantom
- phishing
- incident-response
cold_box_version: 2
inspired_by: implementing-soar-playbook-for-phishing
---

# Implementing Soar Playbook For Phishing (cold-box)

> **Journal ID:** `CB-SKL-283` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-283`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-soar-playbook-for-phishing")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-soar-playbook-for-phishing")` → note **`CB-SKL-283`**
2. `log_skill(case_id, journal_id="CB-SKL-283", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-283` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing soar playbook for phishing capabilities in your environment
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
  "purpose": "[CB-SKL-283] file per playbook step",
  "why": "Executing cb-implementing-soar-playbook-for-phishing \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-283` (`cb-implementing-soar-playbook-for-phishing`)

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

This skill implements a phishing incident response workflow using the Splunk SOAR (formerly Phantom) REST API. When a suspected phishing email is reported, the agent parses email headers and body, creates a SOAR container representing the incident, attaches artifacts containing indicators of compromise (sender address, URLs, IP addresses, file hashes), triggers an automated investigation playbook, and polls for action results.

Splunk SOAR orchestrates and automates security operations through playbooks that chain together investigative and response actions. The REST API at `/rest/container`, `/rest/artifact`, and `/rest/playbook_run` enables programmatic incident creation and automation triggering from external tools, email gateways, and SIEM alerts.


## When to Use

- When deploying or configuring implementing soar playbook for phishing capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Python 3.9 or later with `requests` and `email` modules
- Splunk SOAR instance (Cloud or On-Premises) with REST API access
- SOAR API token with permissions to create containers and trigger playbooks
- Network connectivity to SOAR instance on port 443
- A configured phishing investigation playbook in SOAR

## Steps

1. **Parse the phishing email**: Read the email file (.eml format) and extract headers including From, To, Subject, Reply-To, Return-Path, Received, Message-ID, X-Mailer, and authentication results (SPF, DKIM, DMARC). Extract URLs and IP addresses from the email body.

2. **Authenticate to SOAR REST API**: Use the API token in the `ph-auth-token` header to authenticate all REST API requests to the SOAR instance.

3. **Create a container**: POST to `/rest/container` with the incident label, name, description, severity, and status. The container represents the phishing incident and receives a container ID in the response.

4. **Add email header artifacts**: POST to `/rest/artifact` with `container_id` and CEF (Common Event Format) fields containing sender address (`fromAddress`), recipient (`toAddress`), subject, originating IP (`sourceAddress`), and Message-ID. Set `run_automation` to False for all but the last artifact.

5. **Add URL artifacts**: For each URL extracted from the email body, create an artifact with CEF field `requestURL` and type `url`. These artifacts feed into URL reputation checks in the playbook.

6. **Trigger the playbook**: POST to `/rest/playbook_run` with the playbook ID or name and the container ID. This initiates the automated investigation workflow.

7. **Poll action results**: GET `/rest/action_run` filtered by container ID to monitor playbook progress. Poll until all actions reach a terminal state (success, failed, or cancelled).

8. **Compile response report**: Aggregate playbook action results into a summary report with verdicts from URL reputation, domain reputation, IP geolocation, and email header analysis.

## Expected Output

```json
{
  "incident": {
    "container_id": 1542,
    "status": "new",
    "severity": "high",
    "artifacts_created": 5
  },
  "playbook": {
    "name": "phishing_investigate",
    "run_id": 892,
    "status": "success",
    "actions_completed": 8
  },
  "verdict": "malicious",
  "indicators": {
    "sender_domain_reputation": "malicious",
    "urls_flagged": 2,
    "spf_result": "fail",
    "dkim_result": "fail"
  }
}
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
