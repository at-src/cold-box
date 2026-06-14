---
name: cb-kubernetes-audit-logs
skill_id: cb-kubernetes-audit-logs
journal_id: CB-SKL-068
description: Cold-box analyst playbook — Kubernetes Audit Logs. Parses Kubernetes
  API server audit logs (JSON lines) to detect exec-into-pod, secret access, RBAC
  modifications, privileged pod creation, and anonymous API access. Builds threat
  detection rules from audit event patterns. Use when investigat
domain: cold-box
subdomain: container-security
tier: core
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- kubernetes-security
- container-security
- audit-log-analysis
- rbac
- privilege-escalation
- k8s-api-server
- threat-detection
cold_box_version: 2
inspired_by: analyzing-kubernetes-audit-logs
---

# Kubernetes Audit Logs (cold-box)

> **Journal ID:** `CB-SKL-068` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-068`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-kubernetes-audit-logs")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-kubernetes-audit-logs")` → note **`CB-SKL-068`**
2. `log_skill(case_id, journal_id="CB-SKL-068", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-068` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing kubernetes audit logs
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
## {timestamp} — skill `CB-SKL-068` (`cb-kubernetes-audit-logs`)

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

- When investigating security incidents that require analyzing kubernetes audit logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with container security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse Kubernetes audit log files (JSON lines format) to detect security-relevant
events including unauthorized access, privilege escalation, and data exfiltration.

```python
import json

with open("/var/log/kubernetes/audit.log") as f:
    for line in f:
        event = json.loads(line)
        verb = event.get("verb")
        resource = event.get("objectRef", {}).get("resource")
        user = event.get("user", {}).get("username")
        if verb == "create" and resource == "pods/exec":
            print(f"Pod exec by {user}")
```

Key events to detect:
1. pods/exec and pods/attach (shell into containers)
2. secrets access (get/list/watch)
3. clusterrolebindings creation (RBAC escalation)
4. Privileged pod creation
5. Anonymous or system:unauthenticated access

## Examples

```python
# Detect secret enumeration
if verb in ("get", "list") and resource == "secrets":
    print(f"Secret access: {user} -> {event['objectRef'].get('name')}")
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
