---
name: cb-cloud-native-threat-hunting-with-aws-detective
skill_id: cb-cloud-native-threat-hunting-with-aws-detective
journal_id: CB-SKL-013
description: Cold-box analyst playbook — Cloud Native Threat Hunting With Aws Detective.
  Hunt for threats in AWS environments using Detective behavior graphs, entity investigation
  timelines, GuardDuty finding correlation, and automated entity profiling across
  IAM users, EC2 instances, and IP addresses.
domain: cold-box
subdomain: cloud-security
tier: core
case_profiles:
- cloud
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- aws-detective
- threat-hunting
- cloud-security
- guardduty
- behavior-graph
- aws
- iam
- ec2
- incident-investigation
cold_box_version: 2
inspired_by: performing-cloud-native-threat-hunting-with-aws-detective
---

# Cloud Native Threat Hunting With Aws Detective (cold-box)

> **Journal ID:** `CB-SKL-013` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-013`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-cloud-native-threat-hunting-with-aws-detective")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-cloud-native-threat-hunting-with-aws-detective")` → note **`CB-SKL-013`**
2. `log_skill(case_id, journal_id="CB-SKL-013", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-013` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Investigation needs structured guidance for: Cloud Native Threat Hunting With Aws Detective
- You need a repeatable sequence before claiming findings in the journal

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
## {timestamp} — skill `CB-SKL-013` (`cb-cloud-native-threat-hunting-with-aws-detective`)

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

AWS Detective automatically collects and analyzes log data from AWS CloudTrail, VPC Flow Logs, GuardDuty findings, and EKS audit logs to build interactive behavior graphs. These graphs enable security analysts to investigate entities (IAM users, roles, IP addresses, EC2 instances) across time, identify anomalous API calls, detect lateral movement between accounts, and correlate GuardDuty findings into coherent attack narratives — all without manual log parsing.

## Prerequisites

- AWS account with Detective enabled (requires GuardDuty active for 48+ hours)
- AWS CLI v2 configured with appropriate IAM permissions (`detective:*`, `guardduty:List*`)
- Python 3.9+ with boto3
- IAM policy: `AmazonDetectiveFullAccess` or custom policy with `detective:SearchGraph`, `detective:GetInvestigation`, `detective:ListIndicators`

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Behavior Graph** | Data structure linking CloudTrail, VPC Flow, GuardDuty, and EKS logs for an account/region |
| **Entity** | Investigable object: IAM user, IAM role, EC2 instance, IP address, S3 bucket, EKS cluster |
| **Finding Group** | Correlated set of GuardDuty findings linked to the same attack campaign |
| **Entity Profile** | Timeline of API calls, network connections, and resource access for a specific entity |
| **Scope Time** | Investigation window (default 24h, max 1 year) for behavioral analysis |

## Steps

### Step 1: List Available Behavior Graphs

```bash
aws detective list-graphs --output table
```

### Step 2: Investigate a Suspicious IAM User

```bash
# Get entity profile for an IAM user
aws detective get-investigation \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001
```

### Step 3: Search Entities Programmatically

```python
#!/usr/bin/env python3
"""Search AWS Detective for suspicious entities."""
import boto3
import json
from datetime import datetime, timedelta

detective = boto3.client('detective')

def list_behavior_graphs():
    """List all Detective behavior graphs."""
    response = detective.list_graphs()
    return response.get('GraphList', [])

def get_investigation_indicators(graph_arn, investigation_id, max_results=50):
    """Get indicators for a specific investigation."""
    response = detective.list_indicators(
        GraphArn=graph_arn,
        InvestigationId=investigation_id,
        MaxResults=max_results
    )
    return response.get('Indicators', [])

def investigate_guardduty_findings(graph_arn):
    """List high-severity investigations correlated by Detective."""
    response = detective.list_investigations(
        GraphArn=graph_arn,
        FilterCriteria={
            'Severity': {'Value': 'CRITICAL'},
            'Status': {'Value': 'RUNNING'}
        },
        MaxResults=20
    )

    for investigation in response.get('InvestigationDetails', []):
        print(f"Investigation: {investigation['InvestigationId']}")
        print(f"  Entity: {investigation['EntityArn']}")
        print(f"  Status: {investigation['Status']}")
        print(f"  Severity: {investigation['Severity']}")
        print(f"  Created: {investigation['CreatedTime']}")
        print()

if __name__ == "__main__":
    graphs = list_behavior_graphs()
    for graph in graphs:
        print(f"Graph: {graph['Arn']}")
        investigate_guardduty_findings(graph['Arn'])
```

### Step 4: Analyze Finding Groups for Attack Campaigns

```bash
# List investigations with high severity
aws detective list-investigations \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --filter-criteria '{"Severity":{"Value":"HIGH"}}' \
  --max-results 10
```

### Step 5: Check Entity Indicators

```bash
# Get indicators for a specific investigation
aws detective list-indicators \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001 \
  --max-results 50
```

## Expected Output

The `list-investigations` command returns investigation metadata:

```json
{
  "InvestigationDetails": [
    {
      "InvestigationId": "000000000000000000001",
      "Severity": "CRITICAL",
      "Status": "RUNNING",
      "State": "ACTIVE",
      "EntityArn": "arn:aws:iam::123456789012:user/suspicious-user",
      "EntityType": "IAM_USER",
      "CreatedTime": "2026-03-15T14:30:00Z"
    }
  ]
}
```

Indicators are retrieved separately via `list-indicators` and include types such as `TTP_OBSERVED`, `IMPOSSIBLE_TRAVEL`, `FLAGGED_IP_ADDRESS`, `NEW_GEOLOCATION`, `NEW_ASO`, `NEW_USER_AGENT`, `RELATED_FINDING`, and `RELATED_FINDING_GROUP`.

## Verification

1. Confirm behavior graph has data: `aws detective list-graphs` returns non-empty list
2. Validate investigation results contain entity timelines with API call sequences
3. Cross-reference Detective findings with raw CloudTrail logs for accuracy
4. Verify finding group correlations match manual investigation conclusions
5. Confirm automated alerts trigger for HIGH/CRITICAL severity investigations

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
