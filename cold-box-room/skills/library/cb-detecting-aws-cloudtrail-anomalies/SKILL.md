---
name: cb-detecting-aws-cloudtrail-anomalies
skill_id: cb-detecting-aws-cloudtrail-anomalies
journal_id: CB-SKL-173
description: Cold-box analyst playbook — Detecting Aws Cloudtrail Anomalies. Detect
  unusual API call patterns in AWS CloudTrail logs using boto3, statistical baselining,
  and behavioral analysis to identify credential compromise, privilege escalation,
  and unauthorized resource access.
domain: cold-box
subdomain: cloud-security
tier: adjacent
case_profiles:
- cloud
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- cloud-security
- aws
- cloudtrail
- anomaly-detection
- threat-detection
- boto3
cold_box_version: 2
inspired_by: detecting-aws-cloudtrail-anomalies
---

# Detecting Aws Cloudtrail Anomalies (cold-box)

> **Journal ID:** `CB-SKL-173` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-173`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-aws-cloudtrail-anomalies")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-aws-cloudtrail-anomalies")` → note **`CB-SKL-173`**
2. `log_skill(case_id, journal_id="CB-SKL-173", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-173` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting aws cloudtrail anomalies
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
## {timestamp} — skill `CB-SKL-173` (`cb-detecting-aws-cloudtrail-anomalies`)

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

AWS CloudTrail records API calls across AWS services. This skill covers querying CloudTrail events with boto3's `lookup_events` API, building statistical baselines of normal API activity, detecting anomalies such as unusual event sources, geographic anomalies, high-frequency API calls, and first-time API usage patterns that indicate compromised credentials or insider threats.


## When to Use

- When investigating security incidents that require detecting aws cloudtrail anomalies
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `boto3` library
- AWS credentials with CloudTrail read permissions (cloudtrail:LookupEvents)
- Understanding of AWS IAM and common API patterns
- CloudTrail enabled in target AWS account (management events at minimum)

## Steps

### Step 1: Query CloudTrail Events
Use boto3 CloudTrail client's lookup_events to retrieve recent API activity with pagination.

### Step 2: Build Activity Baseline
Aggregate events by user, source IP, event source, and event name to establish normal behavior patterns.

### Step 3: Detect Anomalies
Flag unusual patterns: new event sources per user, first-time API calls, geographic IP changes, high error rates, and sensitive API usage (IAM, KMS, S3 policy changes).

### Step 4: Generate Detection Report
Produce a JSON report with anomaly scores, top suspicious users, and recommended investigation actions.

## Expected Output

JSON report with event statistics, baseline deviations, anomalous users/IPs, sensitive API calls, and error rate analysis.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
