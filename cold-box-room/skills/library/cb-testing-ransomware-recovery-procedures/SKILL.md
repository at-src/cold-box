---
name: cb-testing-ransomware-recovery-procedures
skill_id: cb-testing-ransomware-recovery-procedures
journal_id: CB-SKL-110
description: Cold-box analyst playbook — Testing Ransomware Recovery Procedures. Test
  and validate ransomware recovery procedures including backup restore operations,
  RTO/RPO target verification, recovery sequencing, and clean restore validation to
  ensure organizational resilience against destructive ransomware attacks.
domain: cold-box
subdomain: incident-response
tier: core
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- incident-response
- ransomware
- disaster-recovery
- backup
- rto
- rpo
- resilience
cold_box_version: 2
inspired_by: testing-ransomware-recovery-procedures
---

# Testing Ransomware Recovery Procedures (cold-box)

> **Journal ID:** `CB-SKL-110` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-110`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-testing-ransomware-recovery-procedures")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-testing-ransomware-recovery-procedures")` → note **`CB-SKL-110`**
2. `log_skill(case_id, journal_id="CB-SKL-110", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-110` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Validating that ransomware recovery plans actually work under realistic conditions
- Measuring RTO (Recovery Time Objective) and RPO (Recovery Point Objective) against business requirements
- Testing backup restore operations to confirm data integrity and completeness after simulated encryption
- Conducting tabletop exercises or live recovery drills for ransomware scenarios
- Auditing disaster recovery readiness as part of compliance or cyber insurance requirements

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sha256sum` | `SIFT-018` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `wc` | `SIFT-026` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-110] sha256sum per playbook step",
  "why": "Executing cb-testing-ransomware-recovery-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-110] grep per playbook step",
  "why": "Executing cb-testing-ransomware-recovery-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-110] find per playbook step",
  "why": "Executing cb-testing-ransomware-recovery-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-110] file per playbook step",
  "why": "Executing cb-testing-ransomware-recovery-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

### `wc` → `SIFT-026`

```json
{
  "tool_id": "SIFT-026",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-110] wc per playbook step",
  "why": "Executing cb-testing-ransomware-recovery-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-110` (`cb-testing-ransomware-recovery-procedures`)

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

Use this skill when:
- Validating that ransomware recovery plans actually work under realistic conditions
- Measuring RTO (Recovery Time Objective) and RPO (Recovery Point Objective) against business requirements
- Testing backup restore operations to confirm data integrity and completeness after simulated encryption
- Conducting tabletop exercises or live recovery drills for ransomware scenarios
- Auditing disaster recovery readiness as part of compliance or cyber insurance requirements

**Do not use** for active incident response during a live ransomware attack. Use dedicated IR playbooks instead.

## Prerequisites

- Isolated recovery test environment (air-gapped or network-segmented lab)
- Access to backup infrastructure (Veeam, Commvault, Rubrik, AWS Backup, Azure Backup)
- Documented RTO/RPO targets per application tier from business impact analysis
- Backup copies available for restore testing (production replicas or test snapshots)
- Recovery runbooks with step-by-step procedures for each critical system

## Workflow

### Step 1: Define Recovery Test Scope

Identify critical systems and their tiered recovery targets:

| Tier | System Type | RTO Target | RPO Target | Example |
|------|------------|------------|------------|---------|
| Tier 1 | Mission-critical | < 1 hour | < 15 min | Active Directory, core database |
| Tier 2 | Business-critical | < 4 hours | < 1 hour | ERP, email, CRM |
| Tier 3 | Business-operational | < 24 hours | < 4 hours | File shares, internal apps |
| Tier 4 | Non-critical | < 72 hours | < 24 hours | Dev/test, analytics |

### Step 2: Prepare Test Environment

```bash
# Verify isolated recovery network is segmented
# No routes to production should exist
ip route show | grep -v "192.168.100.0/24"  # recovery VLAN only

# Verify backup catalog is accessible
restic snapshots --repo s3:s3.amazonaws.com/backup-bucket --password-file /etc/restic/pw
# Or for Veeam:
# Get-VBRBackup | Where-Object {$_.JobType -eq "Backup"} | Select Name, LastPointCreationTime
```

### Step 3: Execute Restore and Measure RTO

For each tiered system, measure the full recovery timeline:

1. **Detection to Decision** - Time from simulated alert to restore decision
2. **Backup Locate** - Time to identify and select the correct clean restore point
3. **Restore Execution** - Time to restore data/VM/application from backup
4. **Validation** - Time to verify data integrity and application functionality
5. **Service Restoration** - Time until the system is fully operational

```
Recovery Timeline Measurement:
  T0: Incident declared (simulated ransomware detection)
  T1: Recovery team assembled and backup identified
  T2: Restore initiated from clean backup
  T3: Restore completed, integrity checks passed
  T4: Application validated and service restored

  Actual RTO = T4 - T0
  Actual RPO = T0 - backup_timestamp
```

### Step 4: Validate Data Integrity Post-Restore

```bash
# Compare file counts between backup manifest and restored data
find /restored/data -type f | wc -l
# Compare against pre-backup manifest

# Verify database consistency after restore
pg_isready -h localhost -p 5432
psql -c "SELECT count(*) FROM critical_table;" -d restored_db

# Hash verification of critical files
sha256sum /restored/data/critical_config.xml
# Compare against known-good hash from backup manifest
```

### Step 5: Test Credential Rotation and Security Hardening

After restore, validate that security controls are re-established:

1. Rotate all service account passwords and API keys
2. Verify MFA is enabled on all administrative accounts
3. Confirm EDR/AV agents are running and reporting to management console
4. Validate firewall rules block known C2 indicators
5. Check that restored systems have latest security patches

### Step 6: Document Results and Calculate Gap

```
Recovery Test Report:
  System: [Name]
  Tier: [1-4]
  RTO Target: [target]    Actual RTO: [measured]    Gap: [delta]
  RPO Target: [target]    Actual RPO: [measured]    Gap: [delta]
  Data Integrity: [PASS/FAIL]
  Application Validation: [PASS/FAIL]
  Security Controls Restored: [PASS/FAIL]

  Status: [MEETS TARGET / EXCEEDS TARGET / FAILS TARGET]
  Remediation Required: [description if FAILS]
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **RTO** | Recovery Time Objective: maximum acceptable downtime for a system after a disaster |
| **RPO** | Recovery Point Objective: maximum acceptable data loss measured in time |
| **WRT** | Work Recovery Time: time to verify system integrity after restore completes |
| **MTD** | Maximum Tolerable Downtime: absolute limit before unacceptable business impact |
| **Clean Restore Point** | A backup verified to be free of ransomware artifacts or encryption |
| **Recovery Sequencing** | The order in which interdependent systems must be restored |
| **Air-Gapped Backup** | Backup stored on media physically disconnected from the network |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Veeam Backup & Replication | VM and physical server backup and restore |
| Commvault | Enterprise data protection and recovery orchestration |
| Rubrik | Cloud-native backup with ransomware recovery SLA |
| AWS Backup | Centralized backup for AWS services |
| Azure Backup | Microsoft cloud backup with immutable vault |
| Restic | Open-source encrypted backup tool |
| Velero | Kubernetes cluster backup and restore |

## Common Pitfalls

- **Not testing restores regularly**: Backups that are never tested often fail when needed. Test quarterly at minimum.
- **Ignoring recovery sequencing**: Restoring an application before its database dependency causes cascading failures.
- **Skipping credential rotation**: Restored systems may contain compromised credentials that allow re-infection.
- **Using production network for testing**: Recovery tests on production networks risk spreading simulated or real infections.
- **Measuring RTO without WRT**: Restore completion is not recovery completion. Include validation and hardening time.
- **No immutable backups**: If ransomware can encrypt or delete backups, recovery is impossible. Use air-gapped or immutable storage.

## References

- NIST SP 800-184: Guide for Cybersecurity Event Recovery
- CISA Ransomware Guide: https://www.cisa.gov/stopransomware
- Veeam RTO/RPO Best Practices: https://www.veeam.com/blog/recovery-time-recovery-point-objectives.html
- NIST CSF 2.0 RC.RP (Recovery Planning)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
