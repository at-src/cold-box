---
name: cb-hunting-for-command-and-control-beaconing
skill_id: cb-hunting-for-command-and-control-beaconing
journal_id: CB-SKL-229
description: Cold-box analyst playbook — Hunting For Command And Control Beaconing.
  Detect C2 beaconing patterns in network traffic using frequency analysis, jitter
  detection, and domain reputation to identify compromised endpoints communicating
  with adversary infrastructure.
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
- mitre-attack
- c2
- beaconing
- network-analysis
- proactive-detection
cold_box_version: 2
inspired_by: hunting-for-command-and-control-beaconing
---

# Hunting For Command And Control Beaconing (cold-box)

> **Journal ID:** `CB-SKL-229` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-229`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-command-and-control-beaconing")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-command-and-control-beaconing")` → note **`CB-SKL-229`**
2. `log_skill(case_id, journal_id="CB-SKL-229", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-229` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When proactively hunting for compromised systems in the network
- After threat intel indicates C2 frameworks targeting your industry
- When investigating periodic outbound connections to suspicious domains
- During incident response to identify active C2 channels
- When DNS query logs show unusual patterns to specific domains

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `zeek` | `SIFT-119` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-229] zeek per playbook step",
  "why": "Executing cb-hunting-for-command-and-control-beaconing \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-229] file per playbook step",
  "why": "Executing cb-hunting-for-command-and-control-beaconing \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-229` (`cb-hunting-for-command-and-control-beaconing`)

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

- When proactively hunting for compromised systems in the network
- After threat intel indicates C2 frameworks targeting your industry
- When investigating periodic outbound connections to suspicious domains
- During incident response to identify active C2 channels
- When DNS query logs show unusual patterns to specific domains

## Prerequisites

- Network proxy/firewall logs with full URL and timing data
- DNS query logs (passive DNS, DNS server logs, or Sysmon Event ID 22)
- Zeek/Bro network connection logs or NetFlow data
- SIEM with statistical analysis capabilities (Splunk, Elastic)
- Threat intelligence feeds for domain/IP reputation

## Workflow

1. **Identify Beaconing Characteristics**: Define what constitutes beaconing (regular intervals, small payload sizes, consistent destinations, jitter patterns).
2. **Collect Network Telemetry**: Aggregate proxy logs, DNS queries, and connection metadata for analysis.
3. **Apply Frequency Analysis**: Identify connections with regular intervals using statistical methods (standard deviation, coefficient of variation).
4. **Filter Known-Good Traffic**: Exclude legitimate periodic traffic (Windows Update, AV updates, heartbeat services, NTP).
5. **Analyze Domain/IP Reputation**: Check identified beaconing destinations against threat intel, WHOIS data, and certificate transparency logs.
6. **Investigate Endpoint Context**: Correlate beaconing activity with process creation, user context, and file system changes on source endpoints.
7. **Confirm and Respond**: Validate C2 activity, block communication, and initiate incident response.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1071 | Application Layer Protocol (HTTP/HTTPS/DNS C2) |
| T1071.001 | Web Protocols (HTTP/S beaconing) |
| T1071.004 | DNS (DNS tunneling C2) |
| T1573 | Encrypted Channel |
| T1572 | Protocol Tunneling |
| T1568 | Dynamic Resolution (DGA, fast-flux) |
| T1132 | Data Encoding in C2 |
| T1095 | Non-Application Layer Protocol |
| Beacon Interval | Time between C2 check-ins |
| Jitter | Random variation in beacon interval |
| DGA | Domain Generation Algorithm |
| Fast-Flux | Rapidly changing DNS resolution |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| RITA (Real Intelligence Threat Analytics) | Automated beacon detection in Zeek logs |
| Splunk | Statistical beacon analysis with SPL |
| Elastic Security | ML-based anomaly detection for beaconing |
| Zeek/Bro | Network connection metadata collection |
| Suricata | Network IDS with JA3/JA4 fingerprinting |
| VirusTotal | Domain and IP reputation checking |
| PassiveDNS | Historical DNS resolution data |
| Flare | C2 profile detection |

## Common Scenarios

1. **Cobalt Strike Beacon**: HTTP/HTTPS beaconing with configurable sleep time and jitter to malleable C2 profiles.
2. **DNS Tunneling C2**: Data exfiltration and command receipt via encoded DNS TXT/CNAME queries to attacker-controlled domains.
3. **Sliver C2 over HTTPS**: Modern C2 framework using HTTPS with configurable beacon intervals and domain fronting.
4. **DGA-based C2**: Malware generating random domains daily, with adversary registering upcoming domains for C2.
5. **Legitimate Service Abuse**: C2 over legitimate cloud services (Azure, AWS, Slack, Discord, Telegram).

## Output Format

```
Hunt ID: TH-C2-[DATE]-[SEQ]
Source IP: [Internal IP]
Source Host: [Hostname]
Destination: [Domain/IP]
Protocol: [HTTP/HTTPS/DNS/Custom]
Beacon Interval: [Average seconds]
Jitter: [Percentage]
Connection Count: [Total connections]
Data Volume: [Bytes sent/received]
First Seen: [Timestamp]
Last Seen: [Timestamp]
Domain Age: [Days]
TI Match: [Yes/No - source]
Risk Level: [Critical/High/Medium/Low]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
