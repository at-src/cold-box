---
name: cb-cloud-incident-containment-procedures
skill_id: cb-cloud-incident-containment-procedures
journal_id: CB-SKL-011
description: Cold-box analyst playbook — Cloud Incident Containment Procedures. Execute
  cloud-native incident containment across AWS, Azure, and GCP by isolating compromised
  resources, revoking credentials, preserving forensic evidence, and applying security
  group restrictions to prevent lateral movement.
domain: cold-box
subdomain: incident-response
tier: core
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- cloud-security
- incident-containment
- aws
- azure
- gcp
- cloud-forensics
- credential-revocation
- network-isolation
cold_box_version: 2
inspired_by: performing-cloud-incident-containment-procedures
---

# Cloud Incident Containment Procedures (cold-box)

> **Journal ID:** `CB-SKL-011` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-011`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-cloud-incident-containment-procedures")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-cloud-incident-containment-procedures")` → note **`CB-SKL-011`**
2. `log_skill(case_id, journal_id="CB-SKL-011", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-011` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing cloud incident containment procedures
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `vol` | `SIFT-173` | no | yes |
| `dd` | `SIFT-034` | no | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-011] powershell per playbook step",
  "why": "Executing cb-cloud-incident-containment-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

### `vol` → `SIFT-173`

```json
{
  "tool_id": "SIFT-173",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-011] vol per playbook step",
  "why": "Executing cb-cloud-incident-containment-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

### `dd` → `SIFT-034`

```json
{
  "tool_id": "SIFT-034",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-011] dd per playbook step",
  "why": "Executing cb-cloud-incident-containment-procedures \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-011` (`cb-cloud-incident-containment-procedures`)

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

Cloud incident containment requires cloud-native approaches that differ significantly from traditional on-premises response. Containment procedures must leverage platform-specific controls including security groups, IAM policies, network ACLs, and service-level isolation to restrict compromised resources while preserving forensic evidence. According to the 2025 Unit 42 Global Incident Response Report, responding to cloud incidents requires understanding shared responsibility models, ephemeral infrastructure, and API-driven operations. Effective containment involves credential revocation, resource isolation, evidence snapshot creation, and automated response playbook execution.


## When to Use

- When conducting security assessments that involve performing cloud incident containment procedures
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Familiarity with incident response concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## AWS Containment Procedures

### 1. Credential Compromise Containment

```bash
# Disable compromised IAM user access keys
aws iam update-access-key --user-name compromised-user \
  --access-key-id AKIA... --status Inactive

# List and disable all access keys for user
aws iam list-access-keys --user-name compromised-user
aws iam delete-access-key --user-name compromised-user --access-key-id AKIA...

# Attach deny-all policy to compromised user
aws iam put-user-policy --user-name compromised-user \
  --policy-name DenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# Revoke all active sessions for IAM role
aws iam put-role-policy --role-name compromised-role \
  --policy-name RevokeOldSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
      }
    }]
  }'

# Invalidate temporary credentials by updating role trust policy
aws iam update-assume-role-policy --role-name compromised-role \
  --policy-document '{"Version":"2012-10-17","Statement":[]}'
```

### 2. EC2 Instance Isolation

```bash
# Create quarantine security group (no inbound, no outbound)
aws ec2 create-security-group --group-name quarantine-sg \
  --description "Quarantine - No traffic allowed" --vpc-id vpc-xxxxx

# Remove all rules from quarantine SG (default allows outbound)
aws ec2 revoke-security-group-egress --group-id sg-quarantine \
  --ip-permissions '[{"IpProtocol":"-1","FromPort":-1,"ToPort":-1,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# Take forensic snapshot BEFORE containment
aws ec2 create-snapshot --volume-id vol-xxxxx \
  --description "Forensic snapshot - IR Case 2025-001" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=IR-Case,Value=2025-001}]'

# Apply quarantine security group to compromised instance
aws ec2 modify-instance-attribute --instance-id i-xxxxx \
  --groups sg-quarantine

# Tag instance as compromised
aws ec2 create-tags --resources i-xxxxx \
  --tags Key=IR-Status,Value=Contained Key=IR-Case,Value=2025-001

# Capture memory (if SSM agent available)
aws ssm send-command --instance-ids i-xxxxx \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["dd if=/dev/mem of=/tmp/memory.dump bs=1M"]'
```

### 3. S3 Bucket Containment

```bash
# Block all public access
aws s3api put-public-access-block --bucket compromised-bucket \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Apply deny policy to bucket
aws s3api put-bucket-policy --bucket compromised-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyAllExceptForensics",
      "Effect": "Deny",
      "NotPrincipal": {"AWS": "arn:aws:iam::ACCOUNT:role/IR-Forensics"},
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::compromised-bucket","arn:aws:s3:::compromised-bucket/*"]
    }]
  }'

# Enable versioning to preserve evidence
aws s3api put-bucket-versioning --bucket compromised-bucket \
  --versioning-configuration Status=Enabled

# Enable Object Lock for evidence preservation
aws s3api put-object-lock-configuration --bucket evidence-bucket \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 365}}
  }'
```

### 4. Lambda Function Containment

```bash
# Set reserved concurrency to 0 (stops all invocations)
aws lambda put-function-concurrency --function-name compromised-function \
  --reserved-concurrent-executions 0

# Remove all event source mappings
aws lambda list-event-source-mappings --function-name compromised-function
aws lambda delete-event-source-mapping --uuid mapping-uuid
```

## Azure Containment Procedures

### 1. Identity Containment

```powershell
# Revoke all user sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "user-object-id"

# Disable user account
Set-AzureADUser -ObjectId "user-object-id" -AccountEnabled $false

# Reset user password
Set-AzureADUserPassword -ObjectId "user-object-id" -Password (
  ConvertTo-SecureString "TempP@ss!" -AsPlainText -Force
) -ForceChangePasswordNextLogin $true

# Block sign-in via Conditional Access (emergency policy)
# Create policy blocking user from all cloud apps

# Revoke Azure AD application consent
Remove-AzureADServiceAppRoleAssignment -ObjectId "sp-object-id" \
  -AppRoleAssignmentId "assignment-id"
```

### 2. VM Isolation

```powershell
# Create Network Security Group with deny-all rules
$nsg = New-AzNetworkSecurityGroup -ResourceGroupName "rg" -Location "eastus" `
  -Name "quarantine-nsg" `
  -SecurityRules @(
    New-AzNetworkSecurityRuleConfig -Name "DenyAllInbound" -Protocol * `
      -Direction Inbound -Priority 100 -SourceAddressPrefix * `
      -SourcePortRange * -DestinationAddressPrefix * `
      -DestinationPortRange * -Access Deny,
    New-AzNetworkSecurityRuleConfig -Name "DenyAllOutbound" -Protocol * `
      -Direction Outbound -Priority 100 -SourceAddressPrefix * `
      -SourcePortRange * -DestinationAddressPrefix * `
      -DestinationPortRange * -Access Deny
  )

# Take disk snapshot for forensics
$vm = Get-AzVM -ResourceGroupName "rg" -Name "compromised-vm"
$snapshotConfig = New-AzSnapshotConfig -SourceUri $vm.StorageProfile.OsDisk.ManagedDisk.Id `
  -Location "eastus" -CreateOption Copy
New-AzSnapshot -ResourceGroupName "rg" -SnapshotName "forensic-snap" -Snapshot $snapshotConfig

# Apply quarantine NSG to VM NIC
$nic = Get-AzNetworkInterface -ResourceGroupName "rg" -Name "compromised-nic"
$nic.NetworkSecurityGroup = $nsg
Set-AzNetworkInterface -NetworkInterface $nic
```

### 3. Storage Account Containment

```powershell
# Remove network access
Update-AzStorageAccountNetworkRuleSet -ResourceGroupName "rg" `
  -Name "storageaccount" -DefaultAction Deny

# Regenerate access keys
New-AzStorageAccountKey -ResourceGroupName "rg" -Name "storageaccount" -KeyName key1
New-AzStorageAccountKey -ResourceGroupName "rg" -Name "storageaccount" -KeyName key2

# Revoke all SAS tokens (by rotating keys)
# Enable immutability for evidence preservation
```

## GCP Containment Procedures

### 1. IAM Containment

```bash
# Remove all IAM bindings for compromised service account
gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json
# Edit policy.json to remove compromised account bindings
gcloud projects set-iam-policy PROJECT_ID policy.json

# Disable service account
gcloud iam service-accounts disable SA_EMAIL

# Delete service account keys
gcloud iam service-accounts keys list --iam-account SA_EMAIL
gcloud iam service-accounts keys delete KEY_ID --iam-account SA_EMAIL
```

### 2. Compute Instance Isolation

```bash
# Create forensic snapshot
gcloud compute disks snapshot compromised-disk \
  --snapshot-names forensic-snap-$(date +%Y%m%d) \
  --zone us-central1-a

# Apply firewall rule to deny all traffic
gcloud compute firewall-rules create quarantine-deny-all \
  --network default --action DENY --rules all \
  --target-tags quarantine --priority 0

# Tag compromised instance
gcloud compute instances add-tags compromised-instance \
  --tags quarantine --zone us-central1-a

# Remove external IP
gcloud compute instances delete-access-config compromised-instance \
  --access-config-name "External NAT" --zone us-central1-a
```

## Evidence Preservation Best Practices

1. **Always snapshot before containment** - Create disk/volume snapshots before network isolation
2. **Preserve CloudTrail/Activity Logs** - Copy logs to write-protected storage
3. **Document all actions** - Timestamp every containment step taken
4. **Use break-glass procedures** - Pre-establish emergency access for IR team
5. **Maintain forensic chain of custody** - Hash all evidence artifacts

## MITRE ATT&CK Cloud Techniques

| Technique | Containment Action |
|-----------|-------------------|
| T1078 - Valid Accounts | Disable accounts, revoke tokens |
| T1530 - Data from Cloud Storage | Lock down bucket/storage policies |
| T1537 - Transfer to Cloud Account | Block cross-account access |
| T1578 - Modify Cloud Compute | Isolate instances, snapshot disks |
| T1552 - Unsecured Credentials | Rotate all access keys and secrets |

## References

- [Sygnia: Cloud Incident Response Best Practices](https://www.sygnia.co/blog/incident-response-to-cloud-security-incidents-aws-azure-and-gcp-best-practices/)
- [Unit 42: Responding to Cloud Incidents](https://unit42.paloaltonetworks.com/responding-to-cloud-incidents/)
- [Wiz: Cloud Incident Response Checklist](https://www.wiz.io/academy/incident-response-checklist)
- [Microsoft Cloud Security Benchmark - IR](https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
