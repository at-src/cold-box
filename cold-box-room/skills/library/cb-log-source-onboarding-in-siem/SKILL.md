---
name: cb-log-source-onboarding-in-siem
skill_id: cb-log-source-onboarding-in-siem
journal_id: CB-SKL-293
description: Cold-box analyst playbook — Log Source Onboarding In Siem. Perform structured
  log source onboarding into SIEM platforms by configuring collectors, parsers, normalization,
  and validation for complete security visibility.
domain: cold-box
subdomain: soc-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- siem
- log-onboarding
- log-management
- data-ingestion
- parsing
- normalization
- soc
cold_box_version: 2
inspired_by: performing-log-source-onboarding-in-siem
---

# Log Source Onboarding In Siem (cold-box)

> **Journal ID:** `CB-SKL-293` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-293`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-log-source-onboarding-in-siem")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-log-source-onboarding-in-siem")` → note **`CB-SKL-293`**
2. `log_skill(case_id, journal_id="CB-SKL-293", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-293` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing log source onboarding in siem
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-293] powershell per playbook step",
  "why": "Executing cb-log-source-onboarding-in-siem \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-293] file per playbook step",
  "why": "Executing cb-log-source-onboarding-in-siem \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-293` (`cb-log-source-onboarding-in-siem`)

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

Log source onboarding is the systematic process of integrating new data sources into a SIEM platform to enable security monitoring and detection. Proper onboarding requires planning data sources, configuring collection agents, building parsers, normalizing fields to a common schema, and validating data quality. According to the UK NCSC, onboarding should prioritize log sources that provide the highest security value relative to their ingestion cost.


## When to Use

- When conducting security assessments that involve performing log source onboarding in siem
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- SIEM platform deployed (Splunk, Elastic, Sentinel, QRadar, or similar)
- Network access from source systems to SIEM collectors
- Administrative access on source systems for agent installation
- Common Information Model (CIM) or equivalent schema documentation
- Change management approval for production system modifications

## Log Source Priority Framework

### Tier 1 - Critical (Onboard First)

| Source | Log Type | Security Value |
|---|---|---|
| Active Directory | Security Event Logs | Authentication, privilege escalation |
| Firewalls | Traffic logs | Network access, C2 detection |
| EDR/AV | Endpoint alerts | Malware, process execution |
| VPN/Remote Access | Connection logs | Unauthorized access |
| DNS Servers | Query logs | C2 beaconing, data exfiltration |
| Email Gateway | Email security logs | Phishing, BEC |

### Tier 2 - High Priority

| Source | Log Type | Security Value |
|---|---|---|
| Web Proxy | HTTP/HTTPS logs | Web-based attacks, data exfiltration |
| Cloud platforms (AWS/Azure/GCP) | Audit logs | Cloud security posture |
| Database servers | Audit/query logs | Data access, SQL injection |
| DHCP/IPAM | Address allocation | Asset tracking |
| File servers | Access logs | Data access monitoring |

### Tier 3 - Standard

| Source | Log Type | Security Value |
|---|---|---|
| Application servers | App logs | Application-level attacks |
| Print servers | Print logs | Data loss prevention |
| Badge/physical access | Access logs | Physical security correlation |
| Network devices (switches/routers) | Syslog | Network anomalies |

## Onboarding Process

### Step 1: Discovery and Assessment

```
1. Identify the log source:
   - System type and version
   - Log format (syslog, CEF, JSON, Windows Events, etc.)
   - Log volume estimate (EPS - events per second)
   - Network location and firewall requirements

2. Assess security value:
   - What threats can this source help detect?
   - Which MITRE ATT&CK techniques does it cover?
   - Is there an existing SIEM parser?

3. Estimate ingestion cost:
   - Daily volume in GB
   - License impact (per-GB or per-EPS pricing)
   - Storage retention requirements
```

### Step 2: Configure Log Collection

#### Syslog-Based Collection (Firewalls, Network Devices)

```conf
# rsyslog configuration for receiving syslog
# /etc/rsyslog.d/10-siem-collection.conf

# UDP reception
module(load="imudp")
input(type="imudp" port="514" ruleset="siem_forwarding")

# TCP reception
module(load="imtcp")
input(type="imtcp" port="514" ruleset="siem_forwarding")

# TLS reception
module(load="imtcp" StreamDriver.AuthMode="x509/name"
       StreamDriver.Mode="1" StreamDriver.Name="gtls")
input(type="imtcp" port="6514" ruleset="siem_forwarding")

ruleset(name="siem_forwarding") {
    # Forward to SIEM
    action(type="omfwd" target="siem.company.com" port="9514"
           protocol="tcp" queue.type="LinkedList"
           queue.filename="siem_fwd" queue.maxdiskspace="1g"
           queue.saveonshutdown="on" action.resumeRetryCount="-1")
}
```

#### Windows Event Log Collection (Splunk Universal Forwarder)

```conf
# inputs.conf on Splunk Universal Forwarder
[WinEventLog://Security]
disabled = 0
index = wineventlog
sourcetype = WinEventLog:Security
evt_resolve_ad_obj = 1
checkpointInterval = 5

[WinEventLog://System]
disabled = 0
index = wineventlog
sourcetype = WinEventLog:System

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = wineventlog
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = wineventlog
sourcetype = XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
```

#### Cloud Log Collection (AWS CloudTrail)

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "CloudTrailToSIEM": {
      "Type": "AWS::CloudTrail::Trail",
      "Properties": {
        "TrailName": "siem-cloudtrail",
        "S3BucketName": "company-cloudtrail-logs",
        "IsLogging": true,
        "IsMultiRegionTrail": true,
        "IncludeGlobalServiceEvents": true,
        "EnableLogFileValidation": true,
        "EventSelectors": [
          {
            "ReadWriteType": "All",
            "IncludeManagementEvents": true,
            "DataResources": [
              {
                "Type": "AWS::S3::Object",
                "Values": ["arn:aws:s3"]
              }
            ]
          }
        ]
      }
    }
  }
}
```

### Step 3: Parse and Normalize

#### Custom Parser Example (Splunk props.conf/transforms.conf)

```conf
# props.conf
[custom:firewall:logs]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%z
MAX_TIMESTAMP_LOOKAHEAD = 30
TRANSFORMS-firewall = firewall_extract_fields
FIELDALIAS-src = src_addr AS src_ip
FIELDALIAS-dst = dst_addr AS dest_ip
EVAL-action = case(fw_action=="allow", "allowed", fw_action=="deny", "blocked", true(), "unknown")
EVAL-vendor_product = "Custom Firewall"
LOOKUP-geo = geo_ip_lookup ip AS dest_ip OUTPUT country, city, latitude, longitude

# transforms.conf
[firewall_extract_fields]
REGEX = ^(\S+)\s+(\S+)\s+action=(\w+)\s+src=(\S+):(\d+)\s+dst=(\S+):(\d+)\s+proto=(\w+)\s+bytes=(\d+)
FORMAT = timestamp::$1 hostname::$2 fw_action::$3 src_addr::$4 src_port::$5 dst_addr::$6 dst_port::$7 protocol::$8 bytes::$9
```

#### CIM Field Mapping

| Raw Field | CIM Field | Data Model |
|---|---|---|
| src_addr | src_ip | Network_Traffic |
| dst_addr | dest_ip | Network_Traffic |
| dst_port | dest_port | Network_Traffic |
| fw_action | action | Network_Traffic |
| bytes_sent + bytes_recv | bytes | Network_Traffic |
| user_name | user | Authentication |
| login_result | action | Authentication |
| process_path | process | Endpoint |

### Step 4: Validate Data Quality

```spl
# Verify events are arriving
index=new_source earliest=-1h
| stats count by sourcetype, host, source

# Check field extraction quality
index=new_source earliest=-1h
| stats count(src_ip) as has_src count(dest_ip) as has_dest count(action) as has_action count by sourcetype
| eval src_coverage=round(has_src/count*100,1)
| eval dest_coverage=round(has_dest/count*100,1)
| eval action_coverage=round(has_action/count*100,1)

# Verify CIM compliance
| datamodel Network_Traffic search
| search sourcetype=new_sourcetype
| stats count by source, sourcetype

# Check for timestamp parsing issues
index=new_source earliest=-1h
| eval time_diff=abs(_time - _indextime)
| stats avg(time_diff) as avg_lag max(time_diff) as max_lag by host
| where avg_lag > 300
```

### Step 5: Enable Detection Coverage

```spl
# Verify existing correlation searches work with new source
index=new_source sourcetype=new_sourcetype
| tstats count from datamodel=Authentication by _time span=1h
| timechart span=1h count

# Create source-specific detection rule
[New Source - Authentication Anomaly]
search = index=new_source sourcetype=new_sourcetype action=failure \
| stats count by src_ip, user \
| where count > 10
```

## Onboarding Checklist

- [ ] Log source assessed and approved
- [ ] Network connectivity verified
- [ ] Collection agent/method configured
- [ ] Log forwarding confirmed
- [ ] Parser/field extraction configured
- [ ] CIM compliance validated
- [ ] Data model acceleration enabled
- [ ] Volume within license budget
- [ ] Retention policy configured
- [ ] Detection rules enabled/created
- [ ] Dashboard updated
- [ ] Documentation completed
- [ ] SOC team notified

## References

- [UK NCSC - Onboarding Systems and Log Sources](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre/onboarding-systems-and-log-sources)
- [Sumo Logic - Cloud SIEM Onboarding Checklist](https://help.sumologic.com/docs/cse/get-started-with-cloud-siem/onboarding-checklist-cse/)
- [SIEM Logging Best Practices - Coralogix](https://coralogix.com/guides/siem/siem-logging/)
- [Huntress - SIEM Implementation Guide](https://www.huntress.com/siem-guide/siem-implementation-guide)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
