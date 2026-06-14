---
name: cb-implementing-immutable-backup-with-restic
skill_id: cb-implementing-immutable-backup-with-restic
journal_id: CB-SKL-267
description: Cold-box analyst playbook — Implementing Immutable Backup With Restic.
  Implements immutable backup strategy using restic with S3-compatible storage and
  object lock for ransomware-resistant data protection. Automates backup creation,
  integrity verification via restic check --read-data, snapshot retention policy
domain: cold-box
subdomain: ransomware-defense
tier: adjacent
case_profiles:
- cloud
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- restic
- backup
- immutable
- ransomware
- s3
- object-lock
- worm
- recovery
cold_box_version: 2
inspired_by: implementing-immutable-backup-with-restic
---

# Implementing Immutable Backup With Restic (cold-box)

> **Journal ID:** `CB-SKL-267` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-267`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-immutable-backup-with-restic")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-immutable-backup-with-restic")` → note **`CB-SKL-267`**
2. `log_skill(case_id, journal_id="CB-SKL-267", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-267` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Establishing ransomware-resistant backup infrastructure with cryptographic integrity verification
- Implementing 3-2-1-1-0 backup strategy where the extra 1 is an immutable copy
- Automating backup verification workflows that test restore capability on a schedule
- Protecting backup repositories from deletion or modification by compromised admin accounts
- Meeting compliance requirements for data retention with tamper-proof storage

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
## {timestamp} — skill `CB-SKL-267` (`cb-implementing-immutable-backup-with-restic`)

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

- Establishing ransomware-resistant backup infrastructure with cryptographic integrity verification
- Implementing 3-2-1-1-0 backup strategy where the extra 1 is an immutable copy
- Automating backup verification workflows that test restore capability on a schedule
- Protecting backup repositories from deletion or modification by compromised admin accounts
- Meeting compliance requirements for data retention with tamper-proof storage

**Do not use** as the sole backup solution without also maintaining offline/air-gapped copies. Object lock protects against logical deletion but not physical storage failure.

## Prerequisites

- restic binary installed (https://restic.readthedocs.io/)
- S3-compatible storage with Object Lock enabled (AWS S3, MinIO, Backblaze B2)
- Python 3.8+ with subprocess module
- AWS CLI or MinIO client (mc) configured for bucket access
- Sufficient storage for backup repository (typically 2-3x source data with deduplication)

## Workflow

### Step 1: Initialize Restic Repository with Encryption

Create an encrypted restic repository on S3-compatible storage with object lock enabled. Restic uses AES-256-CTR for encryption with Poly1305-AES for authentication, ensuring backup data is both confidential and tamper-evident.

### Step 2: Configure Object Lock Retention

Enable S3 Object Lock in Compliance mode on the backup bucket to prevent any principal (including root) from deleting or modifying objects during the retention period. Set retention to match your backup window requirements (typically 30-90 days).

### Step 3: Automate Backup and Verification

Schedule backup operations with post-backup integrity verification using `restic check --read-data` which downloads and verifies every data blob against its stored checksum. Log results and alert on any integrity failures.

### Step 4: Test Restore Procedures

Periodically restore random files from backup snapshots to a temporary location and compare checksums against the original to validate end-to-end backup integrity. Document restore times for RTO planning.

## Key Concepts

| Term | Definition |
|------|------------|
| **Object Lock** | S3 feature that prevents object deletion or overwrite for a specified retention period |
| **Compliance Mode** | Object Lock mode where even the root account cannot delete objects before retention expires |
| **Deduplication** | Restic stores data in content-addressable chunks, deduplicating across all snapshots |
| **3-2-1-1-0** | 3 copies, 2 media types, 1 offsite, 1 immutable, 0 errors in verification |

## Tools & Systems

- **restic**: Fast, secure, cross-platform backup tool with built-in encryption and deduplication
- **resticpy**: Python wrapper for restic CLI operations
- **AWS S3 Object Lock**: WORM storage for tamper-proof backup retention
- **MinIO**: Self-hosted S3-compatible storage with Object Lock support

## Output Format

```
BACKUP VERIFICATION REPORT
===========================
Repository: s3:s3.amazonaws.com/company-backups-immutable
Snapshots: 45
Total Size: 2.3 TiB (deduplicated from 8.7 TiB)
Last Backup: 2026-03-11T02:00:00Z
Integrity Check: PASSED (all packs verified)
Object Lock: Compliance mode, 90-day retention
Restore Test: PASSED (15 files verified)
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
