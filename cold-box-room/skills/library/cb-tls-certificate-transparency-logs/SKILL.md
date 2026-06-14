---
name: cb-tls-certificate-transparency-logs
skill_id: cb-tls-certificate-transparency-logs
journal_id: CB-SKL-334
description: Cold-box analyst playbook — Tls Certificate Transparency Logs. Queries
  Certificate Transparency logs via crt.sh and pycrtsh to detect phishing domains,
  unauthorized certificate issuance, and shadow IT. Monitors newly issued certificates
  for typosquatting and brand impersonation using Levenshtein distan
domain: cold-box
subdomain: security-operations
tier: adjacent
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- certificate-transparency
- ct-logs
- crt-sh
- phishing-detection
- tls-monitoring
- security-operations
cold_box_version: 2
inspired_by: analyzing-tls-certificate-transparency-logs
---

# Tls Certificate Transparency Logs (cold-box)

> **Journal ID:** `CB-SKL-334` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-334`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-tls-certificate-transparency-logs")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-tls-certificate-transparency-logs")` → note **`CB-SKL-334`**
2. `log_skill(case_id, journal_id="CB-SKL-334", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-334` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing tls certificate transparency logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `find` | `SIFT-009` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-334] find per playbook step",
  "why": "Executing cb-tls-certificate-transparency-logs \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-334` (`cb-tls-certificate-transparency-logs`)

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

- When investigating security incidents that require analyzing tls certificate transparency logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Query crt.sh Certificate Transparency database to find certificates issued for
domains similar to your organization's brand, detecting phishing infrastructure.

```python
from pycrtsh import Crtsh

c = Crtsh()
# Search for certificates matching a domain
certs = c.search("example.com")
for cert in certs:
    print(cert["id"], cert["name_value"])

# Get full certificate details
details = c.get(certs[0]["id"], type="id")
```

Key analysis steps:
1. Query crt.sh for all certificates matching your domain pattern
2. Identify certificates with typosquatting variations (Levenshtein distance)
3. Flag certificates from unexpected CAs
4. Monitor for wildcard certificates on suspicious subdomains
5. Cross-reference with known phishing infrastructure

## Examples

```python
from pycrtsh import Crtsh
c = Crtsh()
certs = c.search("%.example.com")
for cert in certs:
    print(f"Issuer: {cert.get('issuer_name')}, Domain: {cert.get('name_value')}")
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
