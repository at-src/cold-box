---
name: cb-cloud-forensics-with-aws-cloudtrail
skill_id: cb-cloud-forensics-with-aws-cloudtrail
journal_id: CB-SKL-154
description: Cold-box analyst playbook — Cloud Forensics With Aws Cloudtrail. Perform
  forensic investigation of AWS environments using CloudTrail logs to reconstruct
  attacker activity, identify compromised credentials, and analyze API call patterns.
domain: cold-box
subdomain: cloud-security
tier: adjacent
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- cloud-security
- aws
- cloudtrail
- forensics
- incident-response
- dfir
- boto3
- s3
cold_box_version: 2
inspired_by: performing-cloud-forensics-with-aws-cloudtrail
---

# Cloud Forensics With Aws Cloudtrail (cold-box)

> **Journal ID:** `CB-SKL-154` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-154`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-cloud-forensics-with-aws-cloudtrail")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-cloud-forensics-with-aws-cloudtrail")` → note **`CB-SKL-154`**
2. `log_skill(case_id, journal_id="CB-SKL-154", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-154` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating suspected AWS account compromise
- After detecting unauthorized API calls or credential exposure
- During incident response involving cloud infrastructure
- When analyzing S3 data exfiltration or IAM privilege escalation
- For post-incident forensic timeline reconstruction

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `jq` | `SIFT-013` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `jq` → `SIFT-013`

```json
{
  "tool_id": "SIFT-013",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-154] jq per playbook step",
  "why": "Executing cb-cloud-forensics-with-aws-cloudtrail \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-154` (`cb-cloud-forensics-with-aws-cloudtrail`)

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

- When investigating suspected AWS account compromise
- After detecting unauthorized API calls or credential exposure
- During incident response involving cloud infrastructure
- When analyzing S3 data exfiltration or IAM privilege escalation
- For post-incident forensic timeline reconstruction

## Prerequisites

- AWS account with CloudTrail enabled (management and data events)
- IAM permissions for cloudtrail:LookupEvents, s3:GetObject, athena:StartQueryExecution
- boto3 Python SDK installed
- CloudTrail logs delivered to S3 with optional Athena table configured
- AWS CLI configured with appropriate credentials

## Workflow

1. **Scope Investigation**: Identify timeframe, affected accounts, and compromised credentials.
2. **Query CloudTrail**: Use boto3 lookup_events or Athena to retrieve relevant API events.
3. **Filter by Indicators**: Search for suspicious user agents, source IPs, and event names.
4. **Reconstruct Timeline**: Build chronological sequence of attacker actions from API calls.
5. **Analyze Access Patterns**: Identify data access, IAM changes, and resource modifications.
6. **Identify Persistence**: Check for new IAM users, access keys, roles, or Lambda functions.
7. **Generate Report**: Produce forensic timeline with findings and remediation steps.

## Key Concepts

| Concept | Description |
|---------|-------------|
| LookupEvents | CloudTrail API to query management events (last 90 days) |
| Athena Queries | SQL queries against CloudTrail logs in S3 for historical analysis |
| User Agent Analysis | Identify tool signatures (AWS CLI, SDK, console, custom) |
| AccessKeyId | Track activity by specific IAM access key |
| EventName | AWS API action name (e.g., GetObject, CreateUser, AssumeRole) |
| sourceIPAddress | Origin IP of API call for geolocation analysis |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| boto3 CloudTrail client | Programmatic CloudTrail event lookup |
| AWS Athena | SQL-based analysis of CloudTrail S3 logs |
| AWS CLI | Command-line CloudTrail queries |
| jq | JSON processing for CloudTrail event parsing |
| CloudTrail Lake | Advanced event data store with SQL query support |

## Output Format

```
Forensic Report: AWS-IR-[DATE]-[SEQ]
Account: [AWS Account ID]
Timeframe: [Start] to [End]
Compromised Credentials: [Access Key IDs]
Suspicious Events: [Count]
Source IPs: [List of attacker IPs]
Actions Taken: [API calls by attacker]
Data Accessed: [S3 objects, secrets, etc.]
Persistence Mechanisms: [New users, keys, roles]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
