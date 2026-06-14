---
name: cb-hunting-credential-stuffing-attacks
skill_id: cb-hunting-credential-stuffing-attacks
journal_id: CB-SKL-227
description: Cold-box analyst playbook — Hunting Credential Stuffing Attacks. Detects
  credential stuffing attacks by analyzing authentication logs for login velocity
  anomalies, ASN diversity, password spray patterns, and geographic distribution of
  failed logins. Uses statistical analysis on Splunk or raw log data. Us
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
- credential-stuffing
- authentication-logs
- login-anomaly
- asn-analysis
- threat-hunting
- account-takeover
cold_box_version: 2
inspired_by: hunting-credential-stuffing-attacks
---

# Hunting Credential Stuffing Attacks (cold-box)

> **Journal ID:** `CB-SKL-227` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-227`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-credential-stuffing-attacks")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-credential-stuffing-attacks")` → note **`CB-SKL-227`**
2. `log_skill(case_id, journal_id="CB-SKL-227", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-227` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting credential stuffing attacks
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
## {timestamp} — skill `CB-SKL-227` (`cb-hunting-credential-stuffing-attacks`)

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

- When investigating security incidents that require hunting credential stuffing attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Analyze authentication logs to detect credential stuffing by identifying patterns
of distributed login failures, high IP diversity, and suspicious ASN distribution.

```python
import pandas as pd
from collections import Counter

# Load auth logs
df = pd.read_csv("auth_logs.csv", parse_dates=["timestamp"])

# Credential stuffing indicator: many IPs trying few accounts
ip_per_account = df[df["status"] == "failed"].groupby("username")["source_ip"].nunique()
accounts_under_attack = ip_per_account[ip_per_account > 50]
```

Key detection indicators:
1. High unique source IPs per failed username
2. Low success rate across many accounts (< 1%)
3. ASN concentration from cloud/proxy providers
4. Geographic impossibility (same account, distant locations)
5. User-agent uniformity across distributed IPs

## Examples

```python
# Password spray: one password tried across many accounts
spray = df[df["status"] == "failed"].groupby(["source_ip", "password_hash"]).agg(
    accounts=("username", "nunique")).reset_index()
sprays = spray[spray["accounts"] > 10]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
