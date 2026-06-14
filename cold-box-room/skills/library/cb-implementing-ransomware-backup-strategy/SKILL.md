---
name: cb-implementing-ransomware-backup-strategy
skill_id: cb-implementing-ransomware-backup-strategy
journal_id: CB-SKL-278
description: Cold-box analyst playbook — Implementing Ransomware Backup Strategy.
  Designs and implements a ransomware-resilient backup strategy following the 3-2-1-1-0
  methodology (3 copies, 2 media types, 1 offsite, 1 immutable/air-gapped, 0 errors
  on restore verification). Configures backup schedules aligned to RPO/RTO
domain: cold-box
subdomain: ransomware-defense
tier: adjacent
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ransomware
- backup
- incident-response
- defense
- recovery
- immutable-storage
cold_box_version: 2
inspired_by: implementing-ransomware-backup-strategy
---

# Implementing Ransomware Backup Strategy (cold-box)

> **Journal ID:** `CB-SKL-278` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-278`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-ransomware-backup-strategy")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-ransomware-backup-strategy")` → note **`CB-SKL-278`**
2. `log_skill(case_id, journal_id="CB-SKL-278", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-278` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Designing backup architecture that withstands ransomware encryption and deletion attempts
- Migrating from traditional backup to ransomware-resilient backup with immutable storage
- Establishing RPO/RTO targets for critical systems and validating them through restore testing
- Isolating backup credentials and infrastructure from the production Active Directory domain
- Meeting cyber insurance requirements for backup resilience and tested recovery capabilities

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `mount` | `SIFT-075` | no | yes |
| `file` | `SIFT-008` | yes | yes |
| `sed` | `SIFT-016` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-278] powershell per playbook step",
  "why": "Executing cb-implementing-ransomware-backup-strategy \u2014 see Procedure section",
  "extra_args": []
}
```

### `mount` → `SIFT-075`

```json
{
  "tool_id": "SIFT-075",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-278] mount per playbook step",
  "why": "Executing cb-implementing-ransomware-backup-strategy \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-278] file per playbook step",
  "why": "Executing cb-implementing-ransomware-backup-strategy \u2014 see Procedure section",
  "extra_args": []
}
```

### `sed` → `SIFT-016`

```json
{
  "tool_id": "SIFT-016",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-278] sed per playbook step",
  "why": "Executing cb-implementing-ransomware-backup-strategy \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-278` (`cb-implementing-ransomware-backup-strategy`)

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

- Designing backup architecture that withstands ransomware encryption and deletion attempts
- Migrating from traditional backup to ransomware-resilient backup with immutable storage
- Establishing RPO/RTO targets for critical systems and validating them through restore testing
- Isolating backup credentials and infrastructure from the production Active Directory domain
- Meeting cyber insurance requirements for backup resilience and tested recovery capabilities

**Do not use** as a substitute for endpoint protection, network segmentation, or incident response planning. Backups are a last line of defense, not a primary prevention control.

## Prerequisites

- Inventory of critical systems, applications, and data classified by business impact (Tier 1/2/3)
- Defined RPO (Recovery Point Objective) and RTO (Recovery Time Objective) per tier
- Backup software supporting immutable repositories (Veeam 12+, Commvault, Rubrik, Cohesity)
- Isolated backup network segment or air-gapped storage infrastructure
- Separate backup admin credentials not joined to the production AD domain

## Workflow

### Step 1: Classify Assets and Define Recovery Objectives

Map all systems into recovery tiers based on business impact:

| Tier | Examples | RPO | RTO | Backup Frequency |
|------|----------|-----|-----|------------------|
| Tier 1 (Critical) | Domain controllers, ERP, databases | 1 hour | 4 hours | Hourly incremental, daily full |
| Tier 2 (Important) | File servers, email, web apps | 4 hours | 12 hours | Every 4 hours incremental, daily full |
| Tier 3 (Standard) | Dev environments, archives | 24 hours | 48 hours | Daily incremental, weekly full |

Document dependencies between systems. Domain controllers and DNS must recover before application servers. Database servers before application tiers.

### Step 2: Implement 3-2-1-1-0 Architecture

Configure backup storage following the extended 3-2-1-1-0 rule:

**Copy 1 - Primary backup on local storage:**
```
# Veeam backup job targeting local repository
# Fast restore for operational recovery
Backup Repository: Local NAS (CIFS/NFS) or SAN
Retention: 14 days of restore points
Encryption: AES-256 with password not stored in AD
```

**Copy 2 - Secondary backup on different media:**
```
# Replicate to secondary site or cloud
# Veeam Backup Copy Job or Scale-Out Backup Repository
Target: AWS S3 / Azure Blob / Wasabi / tape library
Retention: 30 days
Transfer: Encrypted TLS 1.2+ in transit
```

**Copy 3 - Offsite copy:**
```
# Geographically separated from primary and secondary
# Cloud object storage in different region or physical tape rotation
Target: Cross-region cloud storage or Iron Mountain tape vaulting
Retention: 90 days
```

**+1 - Immutable or air-gapped copy:**
```
# Cannot be modified or deleted for defined retention period
# Veeam Hardened Repository on Linux with immutable flag
# Or AWS S3 Object Lock in Compliance mode
# Or physical air-gapped tape
```

**+0 - Zero errors on restore verification:**
```
# Automated restore testing using Veeam SureBackup or equivalent
# Scheduled weekly for Tier 1, monthly for Tier 2/3
# Verify boot, network connectivity, and application health
```

### Step 3: Isolate Backup Credentials

Ransomware operators target backup infrastructure by compromising backup admin credentials through Active Directory:

1. **Separate backup admin accounts** from the production AD domain. Use local accounts on backup servers or a dedicated backup management domain.
2. **Dedicated backup network segment** with firewall rules allowing only backup traffic (specific ports, specific source/destination IPs).
3. **MFA on backup console access** using hardware tokens or authenticator apps, not SMS.
4. **Disable RDP** on backup servers. Use out-of-band management (iLO/iDRAC/IPMI) for emergency access.
5. **Remove backup servers from domain** or place in a dedicated OU with restricted GPO inheritance.

```bash
# Linux Hardened Repository - disable SSH password auth
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Set immutable flag on backup files (XFS filesystem)
sudo chattr +i /mnt/backup/repository/*

# Veeam Hardened Repository uses single-use credentials
# that are not stored on the Veeam server after initial setup
```

### Step 4: Configure Immutable Storage

**Veeam Hardened Linux Repository:**
```bash
# Minimal Ubuntu 22.04 LTS installation
# No GUI, no unnecessary services
# Veeam uses temporary SSH credentials during backup window only

# Configure XFS with reflink support
sudo mkfs.xfs -b size=4096 -m reflink=1 /dev/sdb1
sudo mount /dev/sdb1 /mnt/veeam-repo

# Create dedicated Veeam user with limited permissions
sudo useradd -m -s /bin/bash veeamuser
sudo mkdir -p /mnt/veeam-repo/backups
sudo chown veeamuser:veeamuser /mnt/veeam-repo/backups
```

**AWS S3 Object Lock (Compliance Mode):**
```bash
# Create bucket with Object Lock enabled
aws s3api create-bucket \
  --bucket company-immutable-backups \
  --object-lock-enabled-for-bucket \
  --region us-east-1

# Set default retention - 30 days compliance mode
aws s3api put-object-lock-configuration \
  --bucket company-immutable-backups \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 30
      }
    }
  }'
```

**Azure Immutable Blob Storage:**
```bash
# Create storage account with immutable storage
az storage container immutability-policy create \
  --account-name backupaccount \
  --container-name immutable-backups \
  --period 30

# Lock the policy (irreversible)
az storage container immutability-policy lock \
  --account-name backupaccount \
  --container-name immutable-backups
```

### Step 5: Automate Restore Testing

Configure automated restore verification on a recurring schedule:

```powershell
# Veeam SureBackup verification job (PowerShell)
# Tests VM boot, network ping, and application health

Add-PSSnapin VeeamPSSnapin
$backupJob = Get-VBRJob -Name "Tier1-DailyBackup"
$sureBackupJob = Get-VSBJob -Name "Tier1-RestoreTest"

# Verify last restore test completed successfully
$lastSession = Get-VSBSession -Job $sureBackupJob -Last
if ($lastSession.Result -ne "Success") {
    Send-MailMessage -To "backup-team@company.com" `
        -Subject "ALERT: SureBackup verification failed" `
        -Body "Tier 1 restore test failed. Last result: $($lastSession.Result)" `
        -SmtpServer "smtp.company.com"
}
```

Document restore test results and maintain a recovery runbook with step-by-step procedures for each tier.

## Key Concepts

| Term | Definition |
|------|------------|
| **3-2-1-1-0** | Extended backup rule: 3 copies, 2 media types, 1 offsite, 1 immutable/air-gapped, 0 restore verification errors |
| **RPO** | Recovery Point Objective: maximum acceptable data loss measured in time (e.g., 1 hour RPO means max 1 hour of data loss) |
| **RTO** | Recovery Time Objective: maximum acceptable downtime before system must be operational |
| **Immutable Backup** | Backup copy that cannot be modified, encrypted, or deleted for a defined retention period, even by administrators |
| **Air-Gapped Backup** | Physically isolated backup with no network connectivity to production systems, providing strongest ransomware protection |
| **Hardened Repository** | Linux-based backup storage with minimal attack surface, no persistent SSH, and immutable file flags |

## Tools & Systems

- **Veeam Backup & Replication 12**: Enterprise backup with Hardened Linux Repository, SureBackup verification, and immutable backup support
- **Rubrik Security Cloud**: Zero-trust backup platform with immutable snapshots, anomaly detection, and air-gapped recovery
- **Commvault**: Backup with Metallic air-gap protection, anomaly detection, and automated recovery orchestration
- **AWS S3 Object Lock**: Cloud-native immutable storage in Compliance or Governance mode for backup copies
- **Cohesity DataProtect**: Backup platform with DataLock immutability, anti-ransomware detection, and instant mass restore

## Common Scenarios

### Scenario: Financial Services Firm Implementing Ransomware-Resilient Backup

**Context**: A mid-size bank with 500 servers, 200TB of data, and regulatory requirements for 7-year retention must redesign backup after a peer institution was hit by ransomware. Current backups use a single Veeam repository on a Windows server joined to the production domain.

**Approach**:
1. Classify all 500 servers into three tiers: 50 Tier 1 (core banking, AD, DNS), 200 Tier 2 (email, file shares, web), 250 Tier 3 (dev, test, archive)
2. Deploy Veeam Hardened Linux Repository on dedicated Ubuntu 22.04 servers with XFS immutability for primary backup
3. Configure S3 Object Lock in Compliance mode for 30-day immutable cloud copy with Veeam Scale-Out Repository capacity tier
4. Establish quarterly tape rotation to Iron Mountain for 7-year regulatory retention
5. Remove all backup servers from the production AD domain and create isolated backup admin accounts with hardware MFA tokens
6. Deploy SureBackup jobs: weekly for Tier 1, monthly for Tier 2, quarterly for Tier 3
7. Conduct annual full recovery drill restoring AD, DNS, core banking, and dependent applications to validate documented RTO

**Pitfalls**:
- Leaving backup admin credentials in the production AD domain where ransomware operators can compromise them via Kerberoasting or DCSync
- Configuring immutable retention periods shorter than the dwell time of typical ransomware (average 21 days), allowing attackers to wait for immutability to expire
- Testing only individual VM restores without testing full application stack recovery including dependencies
- Forgetting to back up backup server configuration (Veeam config database, encryption keys) separately from the backup infrastructure itself

## Output Format

```
## Ransomware Backup Strategy Assessment

**Organization**: [Name]
**Assessment Date**: [Date]
**Assessor**: [Name]

### Current State
- Backup Solution: [Product/Version]
- Copies: [Number and locations]
- Immutable Copy: [Yes/No - Details]
- Air-Gapped Copy: [Yes/No - Details]
- Credential Isolation: [Yes/No - Details]
- Last Restore Test: [Date - Result]

### Gap Analysis
| Control | Current | Target | Gap | Priority |
|---------|---------|--------|-----|----------|
| Immutable backup | None | S3 Object Lock + Linux Hardened Repo | Missing | Critical |
| Credential isolation | Domain-joined | Standalone local accounts + MFA | Partial | Critical |
| Restore testing | Ad-hoc manual | Automated weekly SureBackup | Missing | High |

### Recommendations
1. [Priority] [Recommendation] - [Estimated effort]
2. ...

### Recovery Tier Summary
| Tier | Systems | RPO | RTO | Backup Schedule | Restore Test Frequency |
|------|---------|-----|-----|-----------------|----------------------|
| 1 | 50 | 1hr | 4hr | Hourly inc/Daily full | Weekly |
| 2 | 200 | 4hr | 12hr | 4hr inc/Daily full | Monthly |
| 3 | 250 | 24hr | 48hr | Daily inc/Weekly full | Quarterly |
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
