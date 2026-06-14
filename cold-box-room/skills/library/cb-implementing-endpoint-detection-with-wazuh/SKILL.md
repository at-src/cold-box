---
name: cb-implementing-endpoint-detection-with-wazuh
skill_id: cb-implementing-endpoint-detection-with-wazuh
journal_id: CB-SKL-260
description: Cold-box analyst playbook — Implementing Endpoint Detection With Wazuh.
  Deploy and configure Wazuh SIEM/XDR for endpoint detection including agent management,
  custom decoder and rule XML creation, alert querying via the Wazuh REST API, and
  automated response actions.
domain: cold-box
subdomain: security-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- siem
- xdr
- wazuh
- endpoint-detection
- custom-rules
- incident-response
cold_box_version: 2
inspired_by: implementing-endpoint-detection-with-wazuh
---

# Implementing Endpoint Detection With Wazuh (cold-box)

> **Journal ID:** `CB-SKL-260` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-260`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-endpoint-detection-with-wazuh")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-endpoint-detection-with-wazuh")` → note **`CB-SKL-260`**
2. `log_skill(case_id, journal_id="CB-SKL-260", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-260` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing endpoint detection with wazuh capabilities in your environment
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
## {timestamp} — skill `CB-SKL-260` (`cb-implementing-endpoint-detection-with-wazuh`)

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

Wazuh is an open-source SIEM and XDR platform for endpoint monitoring, threat detection, and compliance. This skill covers managing agents via the Wazuh REST API, creating custom decoders and rules in XML for organization-specific detections, querying alerts, and testing rule logic using the logtest endpoint.


## When to Use

- When deploying or configuring implementing endpoint detection with wazuh capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Wazuh Manager 4.x deployed with API enabled
- Python 3.9+ with `requests` library
- API credentials (username/password for JWT authentication)
- Understanding of Wazuh decoder and rule XML syntax

## Steps

### Step 1: Authenticate to Wazuh API
Obtain JWT token via POST to /security/user/authenticate.

### Step 2: List and Monitor Agents
Query agent status, versions, and last keep-alive via /agents endpoint.

### Step 3: Query Security Alerts
Search alerts by rule ID, severity, agent, or time range.

### Step 4: Test Custom Rules with Logtest
Use the /logtest endpoint to validate decoder and rule logic against sample log lines.

## Expected Output

JSON report with agent inventory, alert statistics, rule coverage, and logtest validation results.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
