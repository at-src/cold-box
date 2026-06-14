---
name: cb-detecting-beaconing-patterns-with-zeek
skill_id: cb-detecting-beaconing-patterns-with-zeek
journal_id: CB-SKL-176
description: Cold-box analyst playbook — Detecting Beaconing Patterns With Zeek. Performs
  statistical analysis of Zeek conn.log connection intervals to detect C2 beaconing
  patterns. Uses the ZAT library to load Zeek logs into Pandas DataFrames, calculates
  inter-arrival time standard deviation, and flags periodic connect
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
- network-security
- zeek
- c2-beaconing
- conn-log-analysis
- zat
- threat-hunting
- statistical-analysis
cold_box_version: 2
inspired_by: detecting-beaconing-patterns-with-zeek
---

# Detecting Beaconing Patterns With Zeek (cold-box)

> **Journal ID:** `CB-SKL-176` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-176`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-beaconing-patterns-with-zeek")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-beaconing-patterns-with-zeek")` → note **`CB-SKL-176`**
2. `log_skill(case_id, journal_id="CB-SKL-176", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-176` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting beaconing patterns with zeek
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `head` | `SIFT-011` | yes | yes |
| `zeek` | `SIFT-119` | no | no |
| `diff` | `SIFT-007` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-176] head per playbook step",
  "why": "Executing cb-detecting-beaconing-patterns-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-176] zeek per playbook step",
  "why": "Executing cb-detecting-beaconing-patterns-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `diff` → `SIFT-007`

```json
{
  "tool_id": "SIFT-007",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-176] diff per playbook step",
  "why": "Executing cb-detecting-beaconing-patterns-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-176` (`cb-detecting-beaconing-patterns-with-zeek`)

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

- When investigating security incidents that require detecting beaconing patterns with zeek
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Load Zeek conn.log data using ZAT (Zeek Analysis Tools), group connections by
source/destination pairs, and compute timing statistics to identify beaconing.

```python
from zat.log_to_dataframe import LogToDataFrame
import numpy as np

log_to_df = LogToDataFrame()
conn_df = log_to_df.create_dataframe('/path/to/conn.log')

# Group by src/dst pair and calculate inter-arrival time
for (src, dst), group in conn_df.groupby(['id.orig_h', 'id.resp_h']):
    times = group['ts'].sort_values()
    intervals = times.diff().dt.total_seconds().dropna()
    if len(intervals) > 10:
        std_dev = np.std(intervals)
        mean_interval = np.mean(intervals)
        # Low std_dev relative to mean = likely beaconing
```

Key analysis steps:
1. Parse Zeek conn.log into DataFrame with ZAT LogToDataFrame
2. Group connections by source IP and destination IP pairs
3. Calculate inter-arrival time intervals between consecutive connections
4. Compute standard deviation and coefficient of variation
5. Flag pairs with low coefficient of variation as potential beacons

## Examples

```python
from zat.log_to_dataframe import LogToDataFrame
log_to_df = LogToDataFrame()
df = log_to_df.create_dataframe('conn.log')
print(df[['id.orig_h', 'id.resp_h', 'ts', 'duration']].head())
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
