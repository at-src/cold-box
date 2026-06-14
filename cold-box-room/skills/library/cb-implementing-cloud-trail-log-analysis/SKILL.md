---
name: cb-implementing-cloud-trail-log-analysis
skill_id: cb-implementing-cloud-trail-log-analysis
journal_id: CB-SKL-256
description: Cold-box analyst playbook — Implementing Cloud Trail Log Analysis. Implementing
  AWS CloudTrail log analysis for security monitoring, threat detection, and forensic
  investigation using Athena, CloudWatch Logs Insights, and SIEM integration to identify
  unauthorized access, privilege escalation, and suspiciou
domain: cold-box
subdomain: cloud-security
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- cloud-security
- aws
- cloudtrail
- log-analysis
- threat-detection
- forensics
cold_box_version: 2
inspired_by: implementing-cloud-trail-log-analysis
---

# Implementing Cloud Trail Log Analysis (cold-box)

> **Journal ID:** `CB-SKL-256` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-256`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-cloud-trail-log-analysis")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-cloud-trail-log-analysis")` → note **`CB-SKL-256`**
2. `log_skill(case_id, journal_id="CB-SKL-256", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-256` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When building security monitoring pipelines for AWS API activity
- When investigating security incidents to trace attacker actions across AWS services
- When compliance requires audit logging of all administrative and data access operations
- When creating detection rules for known attack patterns in AWS environments
- When establishing baseline API behavior for anomaly detection

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sort` | `SIFT-020` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-256] sort per playbook step",
  "why": "Executing cb-implementing-cloud-trail-log-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-256] find per playbook step",
  "why": "Executing cb-implementing-cloud-trail-log-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-256] file per playbook step",
  "why": "Executing cb-implementing-cloud-trail-log-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-256` (`cb-implementing-cloud-trail-log-analysis`)

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

- When building security monitoring pipelines for AWS API activity
- When investigating security incidents to trace attacker actions across AWS services
- When compliance requires audit logging of all administrative and data access operations
- When creating detection rules for known attack patterns in AWS environments
- When establishing baseline API behavior for anomaly detection

**Do not use** for real-time threat detection (use GuardDuty which already analyzes CloudTrail), for application-level logging (use CloudWatch Application Logs), or for network traffic analysis (use VPC Flow Logs).

## Prerequisites

- CloudTrail enabled with management events and optionally data events across all accounts
- S3 bucket configured as CloudTrail delivery channel with appropriate retention policies
- Amazon Athena configured with CloudTrail log table for ad-hoc queries
- CloudWatch Logs subscription for real-time analysis with Logs Insights
- SIEM integration (Splunk, Elastic, or Security Lake) for production monitoring

## Workflow

### Step 1: Configure CloudTrail for Comprehensive Logging

Ensure CloudTrail captures all relevant event types across the organization.

```bash
# Create an organization trail (captures all accounts)
aws cloudtrail create-trail \
  --name org-security-trail \
  --s3-bucket-name cloudtrail-logs-org-ACCOUNT \
  --is-organization-trail \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation \
  --kms-key-id alias/cloudtrail-key \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:ACCOUNT:log-group:cloudtrail-org:* \
  --cloud-watch-logs-role-arn arn:aws:iam::ACCOUNT:role/CloudTrailCloudWatchRole

# Start logging
aws cloudtrail start-logging --name org-security-trail

# Enable data events for S3 and Lambda
aws cloudtrail put-event-selectors \
  --trail-name org-security-trail \
  --advanced-event-selectors '[
    {
      "Name": "S3DataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}
      ]
    },
    {
      "Name": "LambdaDataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}
      ]
    }
  ]'

# Verify trail configuration
aws cloudtrail describe-trails --trail-name-list org-security-trail
```

### Step 2: Set Up Athena for CloudTrail Query Analysis

Create an Athena table for querying CloudTrail logs with SQL.

```sql
-- Create CloudTrail Athena table
CREATE EXTERNAL TABLE cloudtrail_logs (
  eventVersion STRING,
  userIdentity STRUCT<
    type:STRING, principalId:STRING, arn:STRING,
    accountId:STRING, invokedBy:STRING,
    accessKeyId:STRING, userName:STRING,
    sessionContext:STRUCT<
      attributes:STRUCT<mfaAuthenticated:STRING, creationDate:STRING>,
      sessionIssuer:STRUCT<type:STRING, principalId:STRING, arn:STRING, accountId:STRING, userName:STRING>
    >
  >,
  eventTime STRING,
  eventSource STRING,
  eventName STRING,
  awsRegion STRING,
  sourceIPAddress STRING,
  userAgent STRING,
  errorCode STRING,
  errorMessage STRING,
  requestParameters STRING,
  responseElements STRING,
  additionalEventData STRING,
  requestId STRING,
  eventId STRING,
  readOnly STRING,
  resources ARRAY<STRUCT<arn:STRING, accountId:STRING, type:STRING>>,
  eventType STRING,
  apiVersion STRING,
  recipientAccountId STRING,
  sharedEventId STRING,
  vpcEndpointId STRING
)
PARTITIONED BY (region STRING, year STRING, month STRING, day STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
LOCATION 's3://cloudtrail-logs-org-ACCOUNT/AWSLogs/ORG_ID/';

-- Add partitions for recent data
ALTER TABLE cloudtrail_logs ADD
  PARTITION (region='us-east-1', year='2026', month='02', day='23')
  LOCATION 's3://cloudtrail-logs-org-ACCOUNT/AWSLogs/ORG_ID/ACCOUNT/CloudTrail/us-east-1/2026/02/23/';
```

### Step 3: Run Security-Focused Athena Queries

Execute queries to detect common attack patterns and suspicious activity.

```sql
-- Detect console logins without MFA
SELECT eventtime, useridentity.username, sourceipaddress, useridentity.arn
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND additionalEventData LIKE '%"MFAUsed":"No"%'
  AND errorcode IS NULL
ORDER BY eventtime DESC;

-- Find IAM privilege escalation attempts
SELECT eventtime, useridentity.arn, eventname, errorcode, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN (
  'CreatePolicyVersion', 'SetDefaultPolicyVersion', 'AttachUserPolicy',
  'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy',
  'CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile',
  'PassRole', 'AssumeRole'
)
ORDER BY eventtime DESC
LIMIT 100;

-- Detect CloudTrail tampering
SELECT eventtime, useridentity.arn, eventname, requestparameters, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors')
ORDER BY eventtime DESC;

-- Find API calls from Tor exit nodes or unusual IPs
SELECT eventtime, useridentity.arn, eventname, sourceipaddress, awsregion
FROM cloudtrail_logs
WHERE sourceipaddress NOT LIKE '10.%'
  AND sourceipaddress NOT LIKE '172.%'
  AND sourceipaddress NOT LIKE '192.168.%'
  AND useridentity.type = 'IAMUser'
  AND errorcode IS NULL
GROUP BY eventtime, useridentity.arn, eventname, sourceipaddress, awsregion
ORDER BY eventtime DESC
LIMIT 200;

-- Detect unauthorized API calls (AccessDenied patterns)
SELECT useridentity.arn, eventname, COUNT(*) as denied_count
FROM cloudtrail_logs
WHERE errorcode IN ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess')
  AND eventtime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY useridentity.arn, eventname
HAVING COUNT(*) > 10
ORDER BY denied_count DESC;
```

### Step 4: Build Real-Time Detection with CloudWatch Logs Insights

Create real-time queries for active security monitoring.

```bash
# Detect root account usage
aws logs start-query \
  --log-group-name cloudtrail-org \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, eventName, sourceIPAddress, userAgent
    | filter userIdentity.type = "Root"
    | sort @timestamp desc
  '

# Detect security group changes
aws logs start-query \
  --log-group-name cloudtrail-org \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, userIdentity.arn, eventName, requestParameters.groupId, sourceIPAddress
    | filter eventName in ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "CreateSecurityGroup"]
    | sort @timestamp desc
  '

# Detect new IAM users or access keys created
aws logs start-query \
  --log-group-name cloudtrail-org \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress
    | filter eventName in ["CreateUser", "CreateAccessKey", "CreateLoginProfile"]
    | sort @timestamp desc
  '
```

### Step 5: Create CloudWatch Metric Filters and Alarms

Set up automated alerting for critical security events based on CIS Benchmark recommendations.

```bash
# CIS 3.1: Unauthorized API calls alarm
aws logs put-metric-filter \
  --log-group-name cloudtrail-org \
  --filter-name unauthorized-api-calls \
  --filter-pattern '{($.errorCode = "*UnauthorizedAccess") || ($.errorCode = "AccessDenied*")}' \
  --metric-transformations '[{"metricName":"UnauthorizedAPICalls","metricNamespace":"CISBenchmark","metricValue":"1"}]'

aws cloudwatch put-metric-alarm \
  --alarm-name cis-unauthorized-api-calls \
  --metric-name UnauthorizedAPICalls --namespace CISBenchmark \
  --statistic Sum --period 300 --threshold 10 \
  --comparison-operator GreaterThanThreshold --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:security-alerts

# CIS 3.3: Root account usage alarm
aws logs put-metric-filter \
  --log-group-name cloudtrail-org \
  --filter-name root-account-usage \
  --filter-pattern '{$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent"}' \
  --metric-transformations '[{"metricName":"RootAccountUsage","metricNamespace":"CISBenchmark","metricValue":"1"}]'

# CIS 3.4: IAM policy changes alarm
aws logs put-metric-filter \
  --log-group-name cloudtrail-org \
  --filter-name iam-policy-changes \
  --filter-pattern '{($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy)}' \
  --metric-transformations '[{"metricName":"IAMPolicyChanges","metricNamespace":"CISBenchmark","metricValue":"1"}]'

# CIS 3.5: CloudTrail configuration changes alarm
aws logs put-metric-filter \
  --log-group-name cloudtrail-org \
  --filter-name cloudtrail-changes \
  --filter-pattern '{($.eventName = StopLogging) || ($.eventName = DeleteTrail) || ($.eventName = UpdateTrail)}' \
  --metric-transformations '[{"metricName":"CloudTrailChanges","metricNamespace":"CISBenchmark","metricValue":"1"}]'
```

## Key Concepts

| Term | Definition |
|------|------------|
| CloudTrail | AWS service that records API calls made to AWS services, providing an audit trail of actions taken by users, roles, and services |
| Management Events | CloudTrail events for control plane operations like creating resources, modifying IAM, and configuring services |
| Data Events | CloudTrail events for data plane operations like S3 object access and Lambda function invocations, providing granular activity logging |
| Log File Validation | CloudTrail feature that creates a digest file for verifying that log files have not been tampered with after delivery |
| CloudTrail Lake | Managed data lake for CloudTrail events enabling SQL-based queries without managing Athena tables or S3 data |
| Organization Trail | Single trail that captures API activity across all accounts in an AWS Organization to a central S3 bucket |

## Tools & Systems

- **Amazon Athena**: Serverless SQL query engine for analyzing CloudTrail logs stored in S3 at scale
- **CloudWatch Logs Insights**: Real-time log query service for interactive CloudTrail analysis within the last 30 days
- **CloudTrail Lake**: Managed event data lake with built-in SQL query capabilities and 7-year retention
- **Amazon Security Lake**: Centralized security data lake that normalizes CloudTrail data into OCSF format for SIEM consumption
- **AWS CloudTrail**: Core audit logging service capturing all API activity across AWS accounts and services

## Common Scenarios

### Scenario: Investigating an IAM Credential Compromise Through CloudTrail

**Context**: GuardDuty alerts on `UnauthorizedAccess:IAMUser/MaliciousIPCaller` for a developer's access key. The security team needs to trace all actions taken by the compromised credential.

**Approach**:
1. Query CloudTrail for all events by the compromised AccessKeyId across all regions
2. Build a timeline of API calls to understand the attack sequence
3. Identify the initial access point (when did the key first appear from a malicious IP)
4. Map all resources created, modified, or accessed by the attacker
5. Check for persistence mechanisms (new users, access keys, Lambda functions, EC2 instances)
6. Verify CloudTrail was not tampered with (check for StopLogging or UpdateTrail events)
7. Document the full attack chain and scope of impact for the incident response report

**Pitfalls**: CloudTrail events can take up to 15 minutes to appear in S3 and CloudWatch Logs. For real-time visibility during active incidents, use CloudTrail Lake or CloudWatch Logs Insights rather than Athena queries against S3. Cross-region attacks require querying multiple region partitions in Athena.

## Output Format

```
CloudTrail Security Analysis Report
======================================
Account: 123456789012
Analysis Period: 2026-02-16 to 2026-02-23
Trail: org-security-trail (organization-wide)

SECURITY EVENTS DETECTED:
  Root account logins:                  2
  Console logins without MFA:           7
  Privilege escalation attempts:       12
  CloudTrail configuration changes:     0
  Security group modifications:        34
  Unauthorized API calls:             156

HIGH-PRIORITY FINDINGS:
[CT-001] Console Login Without MFA
  User: admin-user
  Time: 2026-02-22T14:30:00Z
  IP: 203.0.113.50
  Action Required: Enforce MFA via IAM policy

[CT-002] IAM Privilege Escalation
  User: dev-user
  Time: 2026-02-23T03:15:00Z
  Events: CreatePolicyVersion -> AttachRolePolicy
  IP: 185.x.x.x (suspicious)
  Action Required: Investigate credential compromise

ALERTING STATUS:
  CIS metric filters configured: 14 / 14
  CloudWatch alarms active: 14 / 14
  Alerts fired (last 7 days): 8
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
