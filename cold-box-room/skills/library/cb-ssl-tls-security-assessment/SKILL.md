---
name: cb-ssl-tls-security-assessment
skill_id: cb-ssl-tls-security-assessment
journal_id: CB-SKL-325
description: Cold-box analyst playbook — Ssl Tls Security Assessment. Assess SSL/TLS
  server configurations using the sslyze Python library to evaluate cipher suites,
  certificate chains, protocol versions, HSTS headers, and known vulnerabilities like
  Heartbleed and ROBOT.
domain: cold-box
subdomain: network-security
tier: adjacent
case_profiles:
- general
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- network-security
- ssl
- tls
- sslyze
- certificate
- cipher-suites
- vulnerability-assessment
cold_box_version: 2
inspired_by: performing-ssl-tls-security-assessment
---

# Ssl Tls Security Assessment (cold-box)

> **Journal ID:** `CB-SKL-325` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-325`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-ssl-tls-security-assessment")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-ssl-tls-security-assessment")` → note **`CB-SKL-325`**
2. `log_skill(case_id, journal_id="CB-SKL-325", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-325` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing ssl tls security assessment
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
## {timestamp} — skill `CB-SKL-325` (`cb-ssl-tls-security-assessment`)

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

Assess SSL/TLS server configurations using sslyze, a fast Python-based scanning library. This skill covers evaluating supported protocol versions (SSLv2/3, TLS 1.0-1.3), cipher suite strength, certificate chain validation, HSTS enforcement, OCSP stapling, and scanning for known vulnerabilities including Heartbleed, ROBOT, and session renegotiation weaknesses.


## When to Use

- When conducting security assessments that involve performing ssl tls security assessment
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Python 3.9+ with `sslyze` library (pip install sslyze)
- Network access to target HTTPS servers on port 443
- Understanding of TLS protocol versions and cipher suite classifications

## Steps

### Step 1: Configure Server Scan
Create ServerScanRequest with ServerNetworkLocation specifying target hostname and port.

### Step 2: Execute TLS Scan
Use sslyze Scanner to queue and execute scans for all TLS check commands concurrently.

### Step 3: Analyze Results
Evaluate accepted cipher suites, certificate validity, protocol versions, and vulnerability scan results.

### Step 4: Generate Security Report
Produce a JSON report with compliance findings and remediation recommendations.

## Expected Output

JSON report with supported protocols, accepted cipher suites, certificate details, vulnerability results (Heartbleed, ROBOT), and HSTS status.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
