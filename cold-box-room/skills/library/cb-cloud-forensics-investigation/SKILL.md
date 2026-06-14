---
name: cb-cloud-forensics-investigation
skill_id: cb-cloud-forensics-investigation
journal_id: CB-SKL-010
description: Cold-box analyst playbook — Cloud Forensics Investigation. Conduct forensic
  investigations in cloud environments by collecting and analyzing logs, snapshots,
  and metadata from AWS, Azure, and GCP services.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- forensics
- cloud-forensics
- aws
- azure
- gcp
- incident-response
- log-analysis
cold_box_version: 2
inspired_by: performing-cloud-forensics-investigation
---

# Cloud Forensics Investigation (cold-box)

> **Journal ID:** `CB-SKL-010` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-010`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-cloud-forensics-investigation")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-cloud-forensics-investigation")` → note **`CB-SKL-010`**
2. `log_skill(case_id, journal_id="CB-SKL-010", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-010` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating a security breach in AWS, Azure, or GCP cloud environments
- For collecting volatile and non-volatile evidence from cloud infrastructure
- When tracing unauthorized access through cloud service API logs
- During incident response requiring preservation of cloud-based evidence
- For analyzing compromised virtual machines, containers, or serverless functions

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `mount` | `SIFT-075` | no | yes |
| `file` | `SIFT-008` | yes | yes |
| `vol` | `SIFT-173` | no | yes |
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `mount` → `SIFT-075`

```json
{
  "tool_id": "SIFT-075",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-010] mount per playbook step",
  "why": "Executing cb-cloud-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-010] file per playbook step",
  "why": "Executing cb-cloud-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `vol` → `SIFT-173`

```json
{
  "tool_id": "SIFT-173",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-010] vol per playbook step",
  "why": "Executing cb-cloud-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `ls` → `SIFT-014`

```json
{
  "tool_id": "SIFT-014",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-010] ls per playbook step",
  "why": "Executing cb-cloud-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-010` (`cb-cloud-forensics-investigation`)

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
- When investigating a security breach in AWS, Azure, or GCP cloud environments
- For collecting volatile and non-volatile evidence from cloud infrastructure
- When tracing unauthorized access through cloud service API logs
- During incident response requiring preservation of cloud-based evidence
- For analyzing compromised virtual machines, containers, or serverless functions

## Prerequisites
- Administrative access to the cloud account under investigation
- AWS CLI, Azure CLI, or gcloud CLI configured with appropriate permissions
- Understanding of cloud-native logging (CloudTrail, Activity Log, Audit Log)
- Forensic workstation with cloud SDKs installed
- Knowledge of IAM, networking, and compute services in target cloud
- Evidence preservation procedures for cloud environments

## Workflow

### Step 1: Preserve Cloud Evidence and Establish Scope

```bash
# === AWS Evidence Preservation ===
# Snapshot compromised EC2 instance volumes
INSTANCE_ID="i-0abc123def456789"
VOLUME_IDS=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
   --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId' --output text)

for vol in $VOLUME_IDS; do
   aws ec2 create-snapshot --volume-id $vol \
      --description "Forensic snapshot - Case 2024-001 - $(date -u)" \
      --tag-specifications "ResourceType=snapshot,Tags=[{Key=Case,Value=2024-001},{Key=Evidence,Value=true}]"
done

# Capture instance metadata
aws ec2 describe-instances --instance-ids $INSTANCE_ID \
   > /cases/case-2024-001/cloud/instance_metadata.json

# Capture security group rules
aws ec2 describe-security-groups --group-ids $(aws ec2 describe-instances \
   --instance-ids $INSTANCE_ID --query 'Reservations[].Instances[].SecurityGroups[].GroupId' --output text) \
   > /cases/case-2024-001/cloud/security_groups.json

# Capture network interfaces
aws ec2 describe-network-interfaces --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" \
   > /cases/case-2024-001/cloud/network_interfaces.json

# Isolate the instance (replace security group with forensic isolation SG)
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID \
   --groups sg-forensic-isolation

# === Azure Evidence Preservation ===
# Snapshot a compromised VM disk
az snapshot create --resource-group forensics-rg \
   --name "case-2024-001-osdisk-snapshot" \
   --source "/subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.Compute/disks/vm-osdisk"

# === GCP Evidence Preservation ===
gcloud compute disks snapshot compromised-disk \
   --snapshot-names="case-2024-001-forensic" \
   --zone=us-central1-a
```

### Step 2: Collect Cloud API and Access Logs

```bash
# === AWS CloudTrail Logs ===
# Download CloudTrail events for the investigation period
aws cloudtrail lookup-events \
   --start-time "2024-01-15T00:00:00Z" \
   --end-time "2024-01-20T23:59:59Z" \
   --max-results 1000 \
   > /cases/case-2024-001/cloud/cloudtrail_events.json

# Filter for specific user activity
aws cloudtrail lookup-events \
   --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
   --start-time "2024-01-15T00:00:00Z" \
   > /cases/case-2024-001/cloud/user_activity.json

# Download S3 access logs
aws s3 sync s3://my-cloudtrail-bucket/AWSLogs/ /cases/case-2024-001/cloud/cloudtrail_s3/

# Query CloudTrail with Athena for large-scale analysis
aws athena start-query-execution \
   --query-string "SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress, errorCode
                   FROM cloudtrail_logs
                   WHERE eventTime BETWEEN '2024-01-15' AND '2024-01-20'
                   AND sourceIPAddress NOT IN ('10.0.0.0/8')
                   ORDER BY eventTime" \
   --result-configuration OutputLocation=s3://forensics-bucket/athena-results/

# === AWS VPC Flow Logs ===
aws logs filter-log-events \
   --log-group-name "vpc-flow-logs" \
   --start-time $(date -d "2024-01-15" +%s000) \
   --end-time $(date -d "2024-01-20" +%s000) \
   --filter-pattern "ACCEPT" \
   > /cases/case-2024-001/cloud/vpc_flow_logs.json

# === Azure Activity Log ===
az monitor activity-log list \
   --start-time "2024-01-15T00:00:00Z" \
   --end-time "2024-01-20T23:59:59Z" \
   --output json > /cases/case-2024-001/cloud/azure_activity.json

# === GCP Audit Logs ===
gcloud logging read 'logName="projects/PROJECT_ID/logs/cloudaudit.googleapis.com%2Factivity"
   AND timestamp>="2024-01-15T00:00:00Z"
   AND timestamp<="2024-01-20T23:59:59Z"' \
   --format=json > /cases/case-2024-001/cloud/gcp_audit.json
```

### Step 3: Analyze IAM and Access Patterns

```bash
# Analyze compromised credentials usage
python3 << 'PYEOF'
import json
from collections import defaultdict

with open('/cases/case-2024-001/cloud/cloudtrail_events.json') as f:
    data = json.load(f)

# Analyze by source IP
ip_events = defaultdict(list)
error_events = []
critical_actions = []

for event in data.get('Events', []):
    ct = json.loads(event.get('CloudTrailEvent', '{}'))
    source_ip = ct.get('sourceIPAddress', 'Unknown')
    event_name = ct.get('eventName', 'Unknown')
    user_arn = ct.get('userIdentity', {}).get('arn', 'Unknown')
    error = ct.get('errorCode')
    timestamp = ct.get('eventTime', '')

    ip_events[source_ip].append(event_name)

    if error:
        error_events.append({'time': timestamp, 'action': event_name, 'error': error, 'ip': source_ip})

    # Flag critical actions
    critical = ['CreateUser', 'CreateAccessKey', 'AttachUserPolicy', 'CreateRole',
                'PutBucketPolicy', 'StopLogging', 'DeleteTrail', 'CreateKeyPair',
                'RunInstances', 'AuthorizeSecurityGroupIngress']
    if event_name in critical:
        critical_actions.append({'time': timestamp, 'action': event_name, 'user': user_arn, 'ip': source_ip})

print("=== SOURCE IP ANALYSIS ===")
for ip, events in sorted(ip_events.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"  {ip}: {len(events)} events ({len(set(events))} unique actions)")

print(f"\n=== ACCESS ERRORS ({len(error_events)} total) ===")
for e in error_events[:10]:
    print(f"  [{e['time']}] {e['action']} -> {e['error']} from {e['ip']}")

print(f"\n=== CRITICAL ACTIONS ({len(critical_actions)} total) ===")
for a in critical_actions:
    print(f"  [{a['time']}] {a['action']} by {a['user']} from {a['ip']}")
PYEOF
```

### Step 4: Acquire and Analyze VM Disk Image

```bash
# Create a forensic analysis instance from the snapshot
SNAPSHOT_ID="snap-0abc123def456789"

# Create volume from snapshot in isolated forensic VPC
FORENSIC_VOL=$(aws ec2 create-volume --snapshot-id $SNAPSHOT_ID \
   --availability-zone us-east-1a \
   --tag-specifications "ResourceType=volume,Tags=[{Key=Case,Value=2024-001}]" \
   --query 'VolumeId' --output text)

# Attach to forensic analysis instance (read-only mount)
aws ec2 attach-volume --volume-id $FORENSIC_VOL \
   --instance-id i-forensic-workstation \
   --device /dev/xvdf

# On the forensic instance, mount read-only
sudo mount -o ro /dev/xvdf1 /mnt/evidence

# Perform standard disk forensics on the mounted volume
# Extract logs, analyze file system, check for persistence
ls /mnt/evidence/var/log/
cp -r /mnt/evidence/var/log/ /cases/case-2024-001/cloud/vm_logs/
cp -r /mnt/evidence/etc/crontab /cases/case-2024-001/cloud/persistence/
cp -r /mnt/evidence/home/*/.ssh/ /cases/case-2024-001/cloud/ssh_keys/
cp -r /mnt/evidence/home/*/.bash_history /cases/case-2024-001/cloud/bash_history/
```

### Step 5: Generate Cloud Forensics Report

```bash
# Compile findings into structured report
python3 << 'PYEOF'
report = """
CLOUD FORENSICS INVESTIGATION REPORT
======================================
Case: 2024-001
Cloud Provider: AWS (Account: 123456789012)
Region: us-east-1
Investigation Period: 2024-01-15 to 2024-01-20

EVIDENCE PRESERVED:
- EC2 Instance Snapshot: snap-0abc123def456789 (i-0abc123def456789)
- CloudTrail Logs: 2024-01-15 to 2024-01-20
- VPC Flow Logs: 2024-01-15 to 2024-01-20
- Instance Metadata: captured and hashed
- Security Group Configuration: captured at time of isolation

FINDINGS:
1. Initial Access:
   - Compromised IAM access key AKIA... used from IP 203.0.113.45
   - First unauthorized API call: 2024-01-15 14:32:00 UTC
   - IP geolocation: Foreign jurisdiction (not company IP range)

2. Persistence:
   - New IAM user 'backup-admin' created with AdministratorAccess
   - New access key pair generated for backup-admin
   - SSH key added to EC2 instance authorized_keys

3. Lateral Movement:
   - S3 bucket policies modified to allow public access
   - Security group rules modified to allow SSH from 0.0.0.0/0
   - 3 additional EC2 instances launched for crypto-mining

4. Data Exfiltration:
   - S3 bucket 'company-confidential' accessed 234 times
   - 12 GB of data downloaded via GetObject API calls
   - Data transferred to external IP 185.x.x.x

5. Anti-Forensics:
   - CloudTrail logging disabled at 2024-01-18 03:00 UTC
   - CloudWatch log groups deleted

RECOMMENDATIONS:
- Rotate all IAM credentials immediately
- Enable MFA on all accounts
- Restore CloudTrail logging
- Review and restrict S3 bucket policies
- Implement GuardDuty for continuous monitoring
"""

with open('/cases/case-2024-001/cloud/cloud_forensics_report.txt', 'w') as f:
    f.write(report)
print(report)
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Cloud API logging | Service logs recording all API calls (CloudTrail, Activity Log, Audit Log) |
| Volume snapshots | Point-in-time copies of cloud disk volumes for forensic preservation |
| VPC Flow Logs | Network traffic metadata logs showing source, destination, and action |
| IAM credential compromise | Unauthorized use of access keys, tokens, or assumed roles |
| Instance metadata | EC2/VM configuration data including network, storage, and security settings |
| Shared responsibility | Cloud provider secures infrastructure; customer secures data and access |
| Evidence volatility | Cloud resources can be terminated; evidence must be preserved quickly |
| Multi-region artifacts | Attacks may span regions requiring cross-region log collection |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| AWS CLI | Command-line interface for AWS service interaction and log collection |
| CloudTrail | AWS API call logging service for investigation and auditing |
| Azure Monitor | Azure logging and diagnostics platform |
| GCP Cloud Logging | Google Cloud audit and access logging service |
| Athena | AWS serverless SQL query service for analyzing CloudTrail logs at scale |
| Prowler | Open-source AWS security assessment and forensic collection tool |
| ScoutSuite | Multi-cloud security auditing tool |
| CADO Response | Cloud-native digital forensics and incident response platform |

## Common Scenarios

**Scenario 1: Compromised IAM Access Keys**
Identify the compromised key in CloudTrail, trace all API calls made with the key, determine the source IPs and actions taken, check for persistence mechanisms (new users, roles, keys), revoke the compromised credentials, assess data access scope.

**Scenario 2: Cryptojacking on EC2 Instances**
Detect unauthorized instance launches in CloudTrail, snapshot the mining instances for analysis, examine security group changes that allowed C2 communication, identify the initial access vector (stolen keys, SSRF), calculate resource costs incurred.

**Scenario 3: S3 Data Breach**
Analyze S3 access logs and CloudTrail for GetObject/PutBucketPolicy events, identify who modified bucket policies to allow public access, determine the scope of data exposure, check for data downloads from unauthorized IPs, assess regulatory reporting requirements.

**Scenario 4: Container Escape in EKS/AKS/GKE**
Collect Kubernetes audit logs and cloud provider logs, analyze pod creation events for privilege escalation attempts, examine node-level logs for container escape evidence, check for unauthorized access to cloud metadata service (169.254.169.254), trace lateral movement to cloud APIs.

## Output Format

```
Cloud Forensics Summary:
  Cloud: AWS (us-east-1) Account: 123456789012
  Investigation: 2024-01-15 to 2024-01-20
  Incident Type: IAM Credential Compromise + Data Exfiltration

  Evidence Collected:
    EBS Snapshots:    3 volumes preserved
    CloudTrail Events: 12,456 (1,234 from attacker IP)
    VPC Flow Logs:    45,678 records
    S3 Access Logs:   2,345 entries

  Attack Timeline:
    2024-01-15 14:32 - Compromised access key first used from 203.0.113.45
    2024-01-15 14:45 - New IAM user created with admin privileges
    2024-01-16 02:00 - S3 bucket policy modified (public access enabled)
    2024-01-16 03:00 - 12 GB downloaded from company-confidential bucket
    2024-01-18 03:00 - CloudTrail logging disabled

  Impact Assessment:
    Data Exposed: 12 GB from 3 S3 buckets
    Resources Created: 3 EC2 instances (crypto mining)
    Estimated Cost: $4,500 in unauthorized compute
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
