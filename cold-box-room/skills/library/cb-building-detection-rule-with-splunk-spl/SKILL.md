---
name: cb-building-detection-rule-with-splunk-spl
skill_id: cb-building-detection-rule-with-splunk-spl
journal_id: CB-SKL-141
description: Cold-box analyst playbook — Building Detection Rule With Splunk Spl.
  Build effective detection rules using Splunk Search Processing Language (SPL) correlation
  searches to identify security threats in SOC environments.
domain: cold-box
subdomain: soc-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- splunk
- spl
- detection-engineering
- correlation-search
- siem
- soc
- threat-detection
- enterprise-security
cold_box_version: 2
inspired_by: building-detection-rule-with-splunk-spl
---

# Building Detection Rule With Splunk Spl (cold-box)

> **Journal ID:** `CB-SKL-141` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-141`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-building-detection-rule-with-splunk-spl")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-building-detection-rule-with-splunk-spl")` → note **`CB-SKL-141`**
2. `log_skill(case_id, journal_id="CB-SKL-141", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-141` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring building detection rule with splunk spl capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — Limited SIFT coverage; treat remaining steps as reference.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-141] powershell per playbook step",
  "why": "Executing cb-building-detection-rule-with-splunk-spl \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-141` (`cb-building-detection-rule-with-splunk-spl`)

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

Splunk Search Processing Language (SPL) is the primary query language used in Splunk Enterprise Security for building correlation searches that detect suspicious events and patterns. A well-crafted detection rule aggregates, correlates, and enriches security events to generate actionable notable events for SOC analysts. Enterprise SIEMs on average cover only 21% of MITRE ATT&CK techniques, making skilled SPL rule writing essential for closing detection gaps.


## When to Use

- When deploying or configuring building detection rule with splunk spl capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Splunk Enterprise Security (ES) deployed and configured
- Access to Splunk Search & Reporting app with appropriate roles
- Understanding of Common Information Model (CIM) data models
- Familiarity with MITRE ATT&CK framework techniques
- Knowledge of the organization's log sources and data flows

## Core SPL Detection Rule Patterns

### 1. Threshold-Based Detection

Detects events exceeding a defined count within a time window.

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| stats count as failed_logins dc(TargetUserName) as unique_users by src_ip
| where failed_logins > 10 AND unique_users > 3
| eval severity="high"
| eval description="Brute force attack detected from ".src_ip." with ".failed_logins." failed logins across ".unique_users." accounts"
```

### 2. Sequence-Based Detection (Failed Login Followed by Success)

Correlates a sequence of events indicating a successful brute force attack.

```spl
index=wineventlog sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval login_status=case(EventCode=4625, "failure", EventCode=4624, "success")
| stats count(eval(login_status="failure")) as failures count(eval(login_status="success")) as successes latest(_time) as last_event by src_ip, TargetUserName
| where failures > 5 AND successes > 0
| eval description="Account ".TargetUserName." compromised via brute force from ".src_ip
| eval urgency="critical"
```

### 3. Anomaly Detection with Baseline Comparison

Compares current activity against a baseline period to detect spikes.

```spl
index=proxy sourcetype=squid
| bin _time span=1h
| stats count as current_count by src_ip, _time
| join src_ip type=left [
    search index=proxy sourcetype=squid earliest=-7d@d latest=-1d@d
    | stats avg(count) as avg_count stdev(count) as stdev_count by src_ip
]
| eval threshold=avg_count + (3 * stdev_count)
| where current_count > threshold
| eval deviation=round((current_count - avg_count) / stdev_count, 2)
| eval description="Anomalous web traffic from ".src_ip." - ".deviation." standard deviations above baseline"
```

### 4. Lateral Movement Detection

Identifies potential lateral movement using Windows logon events.

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3
| where NOT match(TargetUserName, ".*\$$")
| stats dc(dest) as unique_hosts values(dest) as hosts by src_ip, TargetUserName
| where unique_hosts > 5
| eval severity=case(unique_hosts > 20, "critical", unique_hosts > 10, "high", true(), "medium")
| eval description=TargetUserName." accessed ".unique_hosts." unique hosts from ".src_ip." via network logon"
```

### 5. Data Exfiltration Detection

Monitors for large outbound data transfers.

```spl
index=firewall sourcetype=pan:traffic action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes_out dc(dest_ip) as unique_destinations by src_ip, user
| eval total_mb=round(total_bytes_out/1048576, 2)
| where total_mb > 500 OR unique_destinations > 50
| lookup asset_lookup ip as src_ip OUTPUT asset_category, asset_owner
| eval severity=case(total_mb > 2000, "critical", total_mb > 1000, "high", true(), "medium")
| eval description=user." transferred ".total_mb."MB to ".unique_destinations." unique destinations"
```

### 6. PowerShell Suspicious Execution Detection

Detects encoded or obfuscated PowerShell commands.

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4104
| where match(ScriptBlockText, "(?i)(encodedcommand|invoke-expression|iex|downloadstring|frombase64string|net\.webclient|invoke-webrequest|bitstransfer|invoke-mimikatz|invoke-shellcode)")
| eval decoded_length=len(ScriptBlockText)
| stats count values(ScriptBlockText) as commands by Computer, UserName
| where count > 0
| eval severity="high"
| eval mitre_technique="T1059.001"
| eval description="Suspicious PowerShell execution on ".Computer." by ".UserName
```

## Building Correlation Searches in Splunk ES

### Step-by-Step Process

1. **Define the Use Case**: Map to MITRE ATT&CK technique and define what behavior to detect
2. **Identify Data Sources**: Determine which indexes and sourcetypes contain relevant events
3. **Write the Base Search**: Build SPL that extracts relevant events
4. **Add Aggregation**: Use `stats`, `eventstats`, or `streamstats` to summarize
5. **Apply Thresholds**: Set conditions with `where` clause that distinguish normal from anomalous
6. **Enrich Context**: Add lookups for asset information, identity data, and threat intelligence
7. **Configure Notable Event**: Set severity, urgency, and description fields
8. **Schedule and Test**: Run against historical data and validate detection accuracy

### Correlation Search Configuration Template

```spl
| tstats summariesonly=true count from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.src, Authentication.user, _time span=5m
| rename "Authentication.*" as *
| stats count as total_failures dc(user) as unique_users values(user) as targeted_users by src
| where total_failures > 20 AND unique_users > 5
| lookup dnslookup clientip as src OUTPUT clienthost as src_dns
| lookup asset_lookup ip as src OUTPUT priority as asset_priority, category as asset_category
| eval urgency=case(asset_priority=="critical", "critical", asset_priority=="high", "high", true(), "medium")
| eval rule_name="Brute Force Against Multiple Accounts"
| eval rule_description="Multiple authentication failures from ".src." targeting ".unique_users." unique accounts"
| eval mitre_attack="T1110.001 - Password Guessing"
```

### Enrichment Best Practices

```spl
| lookup identity_lookup identity as user OUTPUT department, manager, risk_score as user_risk
| lookup asset_lookup ip as src_ip OUTPUT asset_name, asset_category, asset_priority, asset_owner
| lookup threatintel_lookup ip as src_ip OUTPUT threat_type, threat_confidence, threat_source
| eval context=case(
    isnotnull(threat_type), "Known threat: ".threat_type,
    user_risk > 80, "High-risk user: risk score ".user_risk,
    asset_priority=="critical", "Critical asset: ".asset_name,
    true(), "Standard context"
)
```

## Performance Optimization

### Use Data Models with tstats

```spl
| tstats summariesonly=true count from datamodel=Network_Traffic
    where All_Traffic.action=allowed
    by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, _time span=1h
| rename "All_Traffic.*" as *
```

### Limit Time Ranges and Use Indexed Fields

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4688
    earliest=-15m latest=now()
| where NOT match(New_Process_Name, "(?i)(svchost|csrss|lsass|services)")
```

### Use Summary Indexing for Historical Baselines

```spl
| tstats count from datamodel=Authentication where Authentication.action=failure by Authentication.src, _time span=1h
| collect index=summary source="auth_failure_baseline" marker="report_name=auth_failure_hourly"
```

## Testing and Validation

### Test Against Known Attack Patterns

```spl
| makeresults count=1
| eval src_ip="10.0.0.50", failed_logins=25, unique_users=8, severity="high"
| eval description="Test brute force detection"
| append [
    search index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
    earliest=-24h latest=now()
    | stats count as failed_logins dc(TargetUserName) as unique_users by src_ip
    | where failed_logins > 10 AND unique_users > 3
    | eval severity="high"
]
```

### Calculate Detection Metrics

```spl
index=notable
| search rule_name="Brute Force*"
| stats count as total_alerts count(eval(status_label="Closed - True Positive")) as true_positives count(eval(status_label="Closed - False Positive")) as false_positives by rule_name
| eval precision=round(true_positives / (true_positives + false_positives) * 100, 2)
| eval fpr=round(false_positives / total_alerts * 100, 2)
```

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | SPL Detection Approach |
|---|---|---|
| T1110.001 | Password Guessing | Threshold on EventCode 4625 by src_ip |
| T1059.001 | PowerShell | Pattern match on EventCode 4104 ScriptBlockText |
| T1021.002 | SMB/Windows Admin Shares | Logon Type 3 with dc(dest) threshold |
| T1048 | Exfiltration Over C2 | bytes_out aggregation over time window |
| T1053.005 | Scheduled Task | EventCode 4698 with suspicious command patterns |
| T1003.001 | LSASS Memory | Process access to lsass.exe via Sysmon EventCode 10 |

## References

- [Splunk ES Correlation Searches Best Practices](https://detect.fyi/splunk-es-correlation-searches-rules-best-cool-practices-06ef94884170)
- [Writing Practical Splunk Detection Rules](https://medium.com/@vitbukac/practical-splunk-detection-rules-how-to-part-1-crawl-a24bc39a4b9d)
- [Configure Correlation Searches - Splunk Documentation](https://help.splunk.com/en/splunk-enterprise-security-8/splunk-app-for-pci-compliance/installation-and-configuration-manual/6.1/configure-correlation-searches/configure-correlation-searches)
- [SOC Prime - Correlation Events in Splunk](https://socprime.com/blog/creating-correlation-events-in-splunk-using-alerts/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
