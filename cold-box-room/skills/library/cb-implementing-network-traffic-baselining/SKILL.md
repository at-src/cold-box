---
name: cb-implementing-network-traffic-baselining
skill_id: cb-implementing-network-traffic-baselining
journal_id: CB-SKL-272
description: Cold-box analyst playbook — Implementing Network Traffic Baselining.
  Build network traffic baselines from NetFlow/IPFIX data using Python pandas for
  statistical analysis, z-score anomaly detection, and hourly/daily traffic pattern
  profiling
domain: cold-box
subdomain: network-security
tier: adjacent
case_profiles:
- network_pcap
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- netflow
- ipfix
- traffic-analysis
- baselining
- anomaly-detection
- pandas
- network-monitoring
cold_box_version: 2
inspired_by: implementing-network-traffic-baselining
---

# Implementing Network Traffic Baselining (cold-box)

> **Journal ID:** `CB-SKL-272` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-272`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-network-traffic-baselining")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-network-traffic-baselining")` → note **`CB-SKL-272`**
2. `log_skill(case_id, journal_id="CB-SKL-272", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-272` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing network traffic baselining capabilities in your environment
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
## {timestamp} — skill `CB-SKL-272` (`cb-implementing-network-traffic-baselining`)

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

Network traffic baselining establishes normal communication patterns by analyzing historical NetFlow/IPFIX data to create statistical profiles of expected behavior. This skill uses Python pandas to compute hourly and daily traffic distributions, per-host byte/packet counts, protocol ratios, and top-N talker profiles. Anomalies are detected using z-score thresholds and IQR (interquartile range) outlier methods, enabling SOC analysts to identify deviations such as data exfiltration spikes, beaconing patterns, and unusual port usage.


## When to Use

- When deploying or configuring implementing network traffic baselining capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- NetFlow v5/v9 or IPFIX flow data exported as CSV or JSON
- Python 3.8+ with pandas and numpy libraries
- Historical flow data (minimum 7 days recommended for baseline)

## Steps

1. Ingest NetFlow/IPFIX records from CSV or JSON exports
2. Compute hourly and daily traffic volume distributions (bytes, packets, flows)
3. Build per-source-IP baseline profiles with mean, median, standard deviation
4. Calculate protocol and port distribution baselines
5. Apply z-score anomaly detection to identify statistical outliers
6. Flag flows exceeding IQR-based thresholds as potential anomalies
7. Generate baseline report with anomaly alerts

## Expected Output

JSON report containing traffic baselines (hourly/daily profiles), per-host statistics, detected anomalies with z-scores, and top talker rankings with deviation indicators.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
