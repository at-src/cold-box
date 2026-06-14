---
name: cb-implementing-privileged-access-management-with-cyberark
skill_id: cb-implementing-privileged-access-management-with-cyberark
journal_id: CB-SKL-276
description: Cold-box analyst playbook — Implementing Privileged Access Management
  With Cyberark. Deploy CyberArk Privileged Access Management to discover, vault,
  rotate, and monitor privileged credentials across enterprise infrastructure. This
  skill covers vault architecture, session isolation, c
domain: cold-box
subdomain: identity-access-management
tier: adjacent
case_profiles:
- general
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- iam
- identity
- access-control
- privileged-access
- pam
- cyberark
cold_box_version: 2
inspired_by: implementing-privileged-access-management-with-cyberark
---

# Implementing Privileged Access Management With Cyberark (cold-box)

> **Journal ID:** `CB-SKL-276` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-276`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-privileged-access-management-with-cyberark")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-privileged-access-management-with-cyberark")` → note **`CB-SKL-276`**
2. `log_skill(case_id, journal_id="CB-SKL-276", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-276` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing privileged access management with cyberark capabilities in your environment
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
## {timestamp} — skill `CB-SKL-276` (`cb-implementing-privileged-access-management-with-cyberark`)

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
Deploy CyberArk Privileged Access Management to discover, vault, rotate, and monitor privileged credentials across enterprise infrastructure. This skill covers vault architecture, session isolation, credential rotation policies, and integration with NIST 800-53 access control requirements.


## When to Use

- When deploying or configuring implementing privileged access management with cyberark capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives
- Design CyberArk vault architecture with high availability
- Implement automated privileged credential discovery and onboarding
- Configure credential rotation policies for different account types
- Deploy Privileged Session Manager (PSM) for session isolation and recording
- Integrate CyberArk with SIEM for privileged access monitoring
- Implement just-in-time (JIT) privileged access workflows

## Key Concepts

### CyberArk Architecture Components
1. **Digital Vault**: Encrypted credential storage with FIPS 140-2 validated encryption
2. **Central Policy Manager (CPM)**: Automated password rotation and verification
3. **Privileged Session Manager (PSM)**: Session isolation, recording, and keystroke logging
4. **Password Vault Web Access (PVWA)**: Web interface for credential management
5. **Privileged Threat Analytics (PTA)**: Behavioral analytics for privileged accounts
6. **Conjur Secrets Manager**: Application identity and secrets management

### Vault Security Model
- **Master Policy**: Global security settings (dual control, exclusive access, one-time passwords)
- **Safes**: Logical containers for credentials with granular permissions
- **Platforms**: Configuration profiles defining rotation, verification, and reconciliation
- **Account Groups**: Link accounts sharing rotation dependencies

### Credential Lifecycle
1. **Discovery**: Scan infrastructure for privileged accounts
2. **Onboarding**: Import accounts into vault with platform assignment
3. **Rotation**: Automated password changes per policy schedule
4. **Verification**: Periodic validation that vaulted credentials work
5. **Reconciliation**: Re-sync credentials when vault and target are out of sync
6. **Decommissioning**: Remove accounts no longer needed

## Workflow

### Step 1: Vault Architecture Design
1. Deploy primary vault server in secured network segment
2. Configure vault high availability with DR vault
3. Harden vault server OS (remove unnecessary services, disable RDP)
4. Configure firewall rules (only port 1858 from authorized components)
5. Set up vault backup with encryption

### Step 2: Safe and Policy Configuration
1. Create safe hierarchy aligned with business units
2. Define safe members with least-privilege roles:
   - Safe Admins: manage safe membership
   - Credential Managers: add/modify accounts
   - Auditors: view audit logs only
   - Users: retrieve/use credentials
3. Configure Master Policy settings:
   - Require dual control for credential retrieval
   - Enable exclusive access (one user per credential at a time)
   - Set one-time password mode for sensitive accounts

### Step 3: Platform Configuration
- Windows Domain Admin: Rotate every 24 hours, verify every 4 hours
- Linux Root: Rotate every 72 hours with SSH key rotation
- Database Admin (Oracle, SQL Server): Rotate every 24 hours
- Network Devices: Rotate every 7 days
- Service Accounts: Rotate on schedule with dependency management
- Cloud IAM Keys: Rotate every 90 days with dual-key strategy

### Step 4: Privileged Session Management
1. Deploy PSM servers behind load balancer
2. Configure session recording (video, keystroke, command logs)
3. Set up session isolation (users connect through PSM, never directly)
4. Define connection components for RDP, SSH, databases, web apps
5. Configure live session monitoring and termination capabilities
6. Set session recording retention (minimum 1 year for compliance)

### Step 5: Integration and Monitoring
1. Forward CyberArk audit logs to SIEM (CEF/Syslog format)
2. Configure PTA for behavioral analytics:
   - Detect credential theft indicators
   - Alert on suspicious privileged session activity
   - Monitor unmanaged privileged account usage
3. Integrate with ticketing system for access request workflows
4. Set up alerts for failed rotation, verification failures, policy violations

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Privileged Access | AC-6(7) | Privileged account controls |
| Credential Management | IA-5 | Automated credential rotation |
| Session Recording | AU-14 | Session audit capability |
| Access Enforcement | AC-3 | Vault-enforced access policies |
| Separation of Duties | AC-5 | Dual control for sensitive operations |

## Common Pitfalls
- Not configuring reconciliation accounts leading to lockouts after rotation
- Setting rotation schedules too aggressive for service accounts with dependencies
- Failing to test PSM connection components before production deployment
- Not establishing break-glass procedures for vault unavailability
- Overlooking network device credential management

## Verification
- [ ] Vault accessible only from authorized components
- [ ] Credential rotation succeeds for all onboarded accounts
- [ ] PSM sessions recorded and searchable
- [ ] Dual control enforced for sensitive credential checkout
- [ ] SIEM receives CyberArk audit events
- [ ] Break-glass procedure tested and documented
- [ ] DR vault failover tested successfully

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
