---
name: cb-hunting-for-beaconing-with-frequency-analysis
skill_id: cb-hunting-for-beaconing-with-frequency-analysis
journal_id: CB-SKL-228
description: Cold-box analyst playbook — Hunting For Beaconing With Frequency Analysis.
  Identify command-and-control beaconing patterns in network traffic by applying statistical
  frequency analysis, jitter calculation, and coefficient of variation scoring to
  detect periodic callbacks from compromised endpoints.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- network_pcap
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- beaconing
- c2-detection
- frequency-analysis
- network-traffic
- RITA
- jitter-detection
- mitre-t1071
cold_box_version: 2
inspired_by: hunting-for-beaconing-with-frequency-analysis
---

# Hunting For Beaconing With Frequency Analysis (cold-box)

> **Journal ID:** `CB-SKL-228` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-228`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-beaconing-with-frequency-analysis")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-beaconing-with-frequency-analysis")` → note **`CB-SKL-228`**
2. `log_skill(case_id, journal_id="CB-SKL-228", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-228` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When proactively searching for compromised endpoints calling back to C2 infrastructure
- After threat intelligence reports indicate active C2 frameworks targeting your sector
- When network logs show periodic outbound connections to unfamiliar destinations
- During purple team exercises validating C2 detection capabilities
- When investigating a potential breach and need to identify active C2 channels

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sort` | `SIFT-020` | yes | yes |
| `zeek` | `SIFT-119` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-228] sort per playbook step",
  "why": "Executing cb-hunting-for-beaconing-with-frequency-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-228] zeek per playbook step",
  "why": "Executing cb-hunting-for-beaconing-with-frequency-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-228` (`cb-hunting-for-beaconing-with-frequency-analysis`)

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

- When proactively searching for compromised endpoints calling back to C2 infrastructure
- After threat intelligence reports indicate active C2 frameworks targeting your sector
- When network logs show periodic outbound connections to unfamiliar destinations
- During purple team exercises validating C2 detection capabilities
- When investigating a potential breach and need to identify active C2 channels

## Prerequisites

- Network proxy/firewall logs with timestamps and destination data (minimum 24 hours)
- Zeek conn.log, dns.log, and ssl.log or equivalent NetFlow/IPFIX data
- SIEM platform with statistical analysis capability (Splunk, Elastic, Microsoft Sentinel)
- RITA (Real Intelligence Threat Analytics) or AC-Hunter for automated beacon analysis
- Threat intelligence feeds for domain/IP reputation enrichment

## Workflow

1. **Define Beacon Parameters**: Establish detection thresholds -- coefficient of variation (CV) below 0.20 indicates strong periodicity, minimum 50 connections over 24 hours, average interval between 30 seconds and 24 hours.
2. **Collect Network Telemetry**: Aggregate proxy logs, DNS queries, firewall connection logs, and Zeek metadata into the analysis platform.
3. **Calculate Connection Intervals**: For each source-destination pair, compute the time delta between consecutive connections and derive mean interval, standard deviation, and CV.
4. **Apply Jitter Analysis**: Sophisticated C2 frameworks like Cobalt Strike add jitter (randomness) to beacon intervals. The Sunburst backdoor beaconed every 15 minutes plus/minus 90 seconds. Analyze jitter patterns to detect even randomized beaconing.
5. **Filter Legitimate Periodic Traffic**: Exclude known-good beaconing sources including Windows Update, antivirus definition updates, NTP synchronization, SaaS heartbeat services, and CDN health checks.
6. **Analyze Data Size Consistency**: C2 heartbeat packets typically have consistent payload sizes. Calculate the CV of bytes transferred per connection -- low variance suggests automated communication.
7. **Enrich with Threat Intelligence**: Check identified beaconing destinations against VirusTotal, WHOIS registration data (flag domains under 30 days old), certificate transparency logs, and passive DNS history.
8. **Correlate with Endpoint Telemetry**: Map beaconing source IPs to endpoint hostnames via DHCP logs, then correlate with process creation events (Sysmon Event ID 1, 3) to identify the responsible process.
9. **Score and Prioritize**: Assign risk scores based on CV value, domain age, TI matches, data size consistency, and suspicious port usage. Escalate high-confidence findings.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1071.001 | Application Layer Protocol: Web Protocols -- HTTP/HTTPS beaconing |
| T1071.004 | Application Layer Protocol: DNS -- DNS-based C2 tunneling |
| T1573 | Encrypted Channel -- TLS/SSL encrypted C2 communication |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms |
| Coefficient of Variation | Standard deviation divided by mean; values below 0.20 indicate periodicity |
| Jitter | Random variation added to beacon interval to evade detection |
| RITA Beacon Score | Composite score from connection regularity, data size consistency, and connection count |
| JA3/JA4 Fingerprinting | TLS client fingerprinting to identify C2 framework signatures |
| Fast-Flux DNS | Rapidly changing DNS resolution used to protect C2 infrastructure |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| RITA (Real Intelligence Threat Analytics) | Automated beacon scoring from Zeek logs |
| AC-Hunter | Commercial threat hunting platform with beacon detection |
| Splunk | SPL-based statistical beacon analysis with streamstats |
| Elastic Security | ML anomaly detection for periodic network behavior |
| Zeek | Network metadata collection (conn.log, dns.log, ssl.log) |
| Suricata | Network IDS with JA3/JA4 TLS fingerprint extraction |
| FLARE | C2 profile and beacon pattern detection |
| VirusTotal | Domain and IP reputation enrichment |

## Detection Queries

### Splunk -- HTTP/S Beacon Frequency Analysis
```spl
index=proxy OR index=firewall
| where NOT match(dest, "(?i)(microsoft|google|amazonaws|cloudflare|akamai)")
| bin _time span=1s
| stats count by src_ip dest _time
| streamstats current=f last(_time) as prev_time by src_ip dest
| eval interval=_time-prev_time
| stats count avg(interval) as avg_interval stdev(interval) as stdev_interval
  min(interval) as min_interval max(interval) as max_interval by src_ip dest
| where count > 50
| eval cv=stdev_interval/avg_interval
| where cv < 0.20 AND avg_interval > 30 AND avg_interval < 86400
| sort cv
| table src_ip dest count avg_interval stdev_interval cv
```

### KQL -- Microsoft Sentinel Beacon Detection
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| summarize ConnectionTimes=make_list(Timestamp), Count=count() by DeviceName, RemoteIP, RemoteUrl
| where Count > 50
| extend Intervals = array_sort_asc(ConnectionTimes)
| mv-apply Intervals on (
    extend NextTime = next(Intervals)
    | where isnotempty(NextTime)
    | extend IntervalSec = datetime_diff('second', NextTime, Intervals)
    | summarize AvgInterval=avg(IntervalSec), StdDev=stdev(IntervalSec)
)
| extend CV = StdDev / AvgInterval
| where CV < 0.2 and AvgInterval > 30
| sort by CV asc
```

### Sigma Rule -- Beaconing Pattern Detection
```yaml
title: Potential C2 Beaconing Pattern Detected
status: experimental
logsource:
    category: proxy
detection:
    selection:
        dst_ip|cidr: '!10.0.0.0/8'
    timeframe: 24h
    condition: selection | count(dst) by src_ip > 50
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001
```

## Common Scenarios

1. **Cobalt Strike Beacon**: Default 60-second interval with configurable 0-50% jitter over HTTPS. Malleable C2 profiles can mimic legitimate traffic patterns.
2. **Sunburst/SUNSPOT**: 12-14 day dormancy period, then beaconing every 12-14 minutes with randomized jitter, designed to evade frequency analysis.
3. **DNS Tunneling C2**: Encoded data exfiltration via DNS TXT/CNAME queries to attacker-controlled domains, detectable via high subdomain entropy and query volume.
4. **Sliver C2**: Modern C2 framework with HTTPS, mTLS, and WireGuard protocols, configurable beacon intervals with built-in jitter support.
5. **Legitimate Service Abuse**: C2 communication over Slack, Discord, Telegram, or cloud storage APIs, making destination-based filtering ineffective.

## Output Format

```
Hunt ID: TH-BEACON-[DATE]-[SEQ]
Source IP: [Internal IP]
Source Host: [Hostname from DHCP/DNS]
Destination: [Domain/IP]
Protocol: [HTTP/HTTPS/DNS]
Beacon Interval: [Average seconds]
Jitter Estimate: [Percentage]
Coefficient of Variation: [CV value]
Connection Count: [Total connections in window]
Data Size CV: [Payload consistency metric]
Domain Age: [Days since registration]
TI Match: [Yes/No -- source]
Risk Score: [0-100]
Risk Level: [Critical/High/Medium/Low]
Indicators: [List of triggered risk factors]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
