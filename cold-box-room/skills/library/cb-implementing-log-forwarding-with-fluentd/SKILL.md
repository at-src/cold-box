---
name: cb-implementing-log-forwarding-with-fluentd
skill_id: cb-implementing-log-forwarding-with-fluentd
journal_id: CB-SKL-268
description: Cold-box analyst playbook — Implementing Log Forwarding With Fluentd.
  Configure Fluentd and Fluent Bit for centralized log aggregation, routing, filtering,
  and enrichment across distributed infrastructure
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
- fluentd
- fluent-bit
- log-aggregation
- log-forwarding
- siem
- centralized-logging
- observability
cold_box_version: 2
inspired_by: implementing-log-forwarding-with-fluentd
---

# Implementing Log Forwarding With Fluentd (cold-box)

> **Journal ID:** `CB-SKL-268` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-268`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-log-forwarding-with-fluentd")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-log-forwarding-with-fluentd")` → note **`CB-SKL-268`**
2. `log_skill(case_id, journal_id="CB-SKL-268", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-268` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing log forwarding with fluentd capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `grep` | `SIFT-010` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-268] grep per playbook step",
  "why": "Executing cb-implementing-log-forwarding-with-fluentd \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-268] file per playbook step",
  "why": "Executing cb-implementing-log-forwarding-with-fluentd \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-268` (`cb-implementing-log-forwarding-with-fluentd`)

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

This skill covers configuring Fluentd and Fluent Bit for centralized log collection, routing, and enrichment. Fluent Bit acts as a lightweight log forwarder on endpoints, while Fluentd serves as the central aggregator and processor. The configuration covers input plugins for syslog, file tailing, and application logs, with output routing to Elasticsearch, S3, and Splunk.


## When to Use

- When deploying or configuring implementing log forwarding with fluentd capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Fluentd (td-agent) v1.16+ or Fluent Bit v3.0+
- Python 3.8+ with fluent-logger library
- Elasticsearch or Splunk for log destination
- Network access on port 24224 (Fluentd forward protocol)
- Ruby 2.7+ (for Fluentd plugin development)

## Steps

1. **Generate Fluent Bit Configuration** — Create input, filter, and output configuration for endpoint log collection
2. **Generate Fluentd Aggregator Configuration** — Configure the central Fluentd instance with forward input, parsing, and multi-output routing
3. **Configure Log Filtering and Enrichment** — Add record_transformer and grep filters for log enrichment and noise reduction
4. **Validate Configuration Syntax** — Parse and validate Fluentd/Fluent Bit configuration files for syntax errors
5. **Test Log Forwarding** — Send test events via fluent-logger Python library and verify delivery
6. **Generate Deployment Report** — Produce configuration summary with routing topology and health metrics

## Expected Output

- Fluent Bit and Fluentd configuration files (INI/YAML format)
- Configuration validation report
- Log routing topology diagram (text-based)
- Test event delivery confirmation

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
