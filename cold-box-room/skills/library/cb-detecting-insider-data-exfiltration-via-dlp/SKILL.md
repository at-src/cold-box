---
name: cb-detecting-insider-data-exfiltration-via-dlp
skill_id: cb-detecting-insider-data-exfiltration-via-dlp
journal_id: CB-SKL-190
description: Cold-box analyst playbook — Detecting Insider Data Exfiltration Via Dlp.
  Detects insider data exfiltration by analyzing DLP policy violations, file access
  patterns, upload volume anomalies, and off-hours activity in endpoint and cloud
  logs. Uses pandas for behavioral analytics and statistical baselines. Use when
domain: cold-box
subdomain: security-operations
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- insider-threat
- data-loss-prevention
- dlp
- exfiltration-detection
- ueba
- security-operations
cold_box_version: 2
inspired_by: detecting-insider-data-exfiltration-via-dlp
---

# Detecting Insider Data Exfiltration Via Dlp (cold-box)

> **Journal ID:** `CB-SKL-190` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-190`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-insider-data-exfiltration-via-dlp")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-insider-data-exfiltration-via-dlp")` → note **`CB-SKL-190`**
2. `log_skill(case_id, journal_id="CB-SKL-190", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-190` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting insider data exfiltration via dlp
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

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
  "purpose": "[CB-SKL-190] file per playbook step",
  "why": "Executing cb-detecting-insider-data-exfiltration-via-dlp \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-190` (`cb-detecting-insider-data-exfiltration-via-dlp`)

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

- When investigating security incidents that require detecting insider data exfiltration via dlp
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Analyze endpoint activity logs, cloud storage access, and email DLP events to detect
data exfiltration patterns using behavioral baselines and statistical anomaly detection.

```python
import pandas as pd

df = pd.read_csv("file_activity.csv", parse_dates=["timestamp"])
# Baseline: average daily upload volume per user
baseline = df.groupby(["user", df["timestamp"].dt.date])["bytes_transferred"].sum()
user_avg = baseline.groupby("user").mean()

# Alert on users exceeding 3x their baseline
today = df[df["timestamp"].dt.date == pd.Timestamp.today().date()]
today_totals = today.groupby("user")["bytes_transferred"].sum()
anomalies = today_totals[today_totals > user_avg * 3]
```

Key indicators:
1. Upload volume exceeding 3x daily baseline
2. Access to files outside normal scope
3. Bulk downloads before resignation
4. Off-hours file access patterns
5. USB/external device usage spikes

## Examples

```python
# Detect off-hours activity
df["hour"] = df["timestamp"].dt.hour
off_hours = df[(df["hour"] < 6) | (df["hour"] > 22)]
suspicious = off_hours.groupby("user").size().sort_values(ascending=False)
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
