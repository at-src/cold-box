---
name: cb-implementing-honeytokens-for-breach-detection
skill_id: cb-implementing-honeytokens-for-breach-detection
journal_id: CB-SKL-266
description: Cold-box analyst playbook — Implementing Honeytokens For Breach Detection.
  Deploys canary tokens and honeytokens (fake AWS credentials, DNS canaries, document
  beacons, database records) that trigger alerts when accessed by attackers. Uses
  the Canarytokens API and custom webhook integrations for breach detection. U
domain: cold-box
subdomain: security-operations
tier: adjacent
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- deception-technology
- honeytokens
- canary-tokens
- breach-detection
- dns-canary
- security-operations
cold_box_version: 2
inspired_by: implementing-honeytokens-for-breach-detection
---

# Implementing Honeytokens For Breach Detection (cold-box)

> **Journal ID:** `CB-SKL-266` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-266`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-honeytokens-for-breach-detection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-honeytokens-for-breach-detection")` → note **`CB-SKL-266`**
2. `log_skill(case_id, journal_id="CB-SKL-266", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-266` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing honeytokens for breach detection capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

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
  "purpose": "[CB-SKL-266] file per playbook step",
  "why": "Executing cb-implementing-honeytokens-for-breach-detection \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-266` (`cb-implementing-honeytokens-for-breach-detection`)

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

- When deploying or configuring implementing honeytokens for breach detection capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Deploy honeytokens across critical systems to detect unauthorized access. Each token
type alerts via webhook when triggered by an attacker.

```python
import requests

# Create a DNS canary token via Canarytokens
resp = requests.post("https://canarytokens.org/generate", data={
    "type": "dns",
    "email": "soc@company.com",
    "memo": "Production DB server honeytoken",
})
token = resp.json()
print(f"DNS token: {token['hostname']}")
```

Token types to deploy:
1. AWS credential files (~/.aws/credentials) with canary keys
2. DNS tokens embedded in configuration files
3. Document beacons (Word/PDF) in sensitive file shares
4. Database honeytoken records in user tables
5. Web bugs in internal wiki/documentation pages

## Examples

```python
# Generate a fake AWS credentials file with canary token
aws_creds = f"[default]\naws_access_key_id = {canary_key_id}\naws_secret_access_key = {canary_secret}\n"
with open("/opt/backup/.aws/credentials", "w") as f:
    f.write(aws_creds)
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
