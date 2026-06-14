---
name: cb-osint-with-spiderfoot
skill_id: cb-osint-with-spiderfoot
journal_id: CB-SKL-304
description: Cold-box analyst playbook — Osint With Spiderfoot. Automate OSINT collection
  using SpiderFoot REST API and CLI for target profiling, module-based reconnaissance,
  and structured result analysis across 200+ data sources
domain: cold-box
subdomain: threat-intelligence
tier: adjacent
case_profiles:
- threat_intel
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- osint
- spiderfoot
- reconnaissance
- threat-intelligence
- attack-surface
- target-profiling
cold_box_version: 2
inspired_by: performing-osint-with-spiderfoot
---

# Osint With Spiderfoot (cold-box)

> **Journal ID:** `CB-SKL-304` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-304`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-osint-with-spiderfoot")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-osint-with-spiderfoot")` → note **`CB-SKL-304`**
2. `log_skill(case_id, journal_id="CB-SKL-304", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-304` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing osint with spiderfoot
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

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
## {timestamp} — skill `CB-SKL-304` (`cb-osint-with-spiderfoot`)

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

SpiderFoot is an open-source OSINT automation tool with 200+ modules that integrates with data sources for threat intelligence and attack surface mapping. This skill uses the SpiderFoot REST API and CLI (sf.py/spiderfoot-cli) to create and manage scans, select modules by use case (footprint, investigate, passive), parse structured results for domains, IPs, email addresses, leaked credentials, and DNS records, and generate target intelligence profiles.


## When to Use

- When conducting security assessments that involve performing osint with spiderfoot
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- SpiderFoot 4.0+ installed or SpiderFoot HX cloud account
- Python 3.8+ with requests library
- SpiderFoot server running on default port 5001
- Optional: API keys for VirusTotal, Shodan, HaveIBeenPwned modules

## Steps

1. Connect to SpiderFoot REST API or use CLI interface
2. Create a new scan with target specification (domain, IP, email, name)
3. Select scan modules by use case (all, footprint, investigate, passive)
4. Monitor scan progress via API polling
5. Retrieve and parse scan results by data element type
6. Extract key findings: subdomains, IPs, emails, leaked credentials
7. Generate structured OSINT intelligence report

## Expected Output

JSON report containing OSINT findings organized by data type (domains, IPs, emails, credentials, DNS records), module source attribution, and target profile summary with risk indicators.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
