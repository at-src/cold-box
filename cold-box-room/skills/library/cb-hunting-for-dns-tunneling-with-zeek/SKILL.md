---
name: cb-hunting-for-dns-tunneling-with-zeek
skill_id: cb-hunting-for-dns-tunneling-with-zeek
journal_id: CB-SKL-233
description: Cold-box analyst playbook — Hunting For Dns Tunneling With Zeek. Detect
  DNS tunneling and data exfiltration by analyzing Zeek dns.log for high-entropy subdomain
  queries, excessive query volume, long query lengths, and unusual DNS record types
  indicating covert channel communication.
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
- dns-tunneling
- zeek
- data-exfiltration
- covert-channel
- mitre-t1071-004
- network-monitoring
cold_box_version: 2
inspired_by: hunting-for-dns-tunneling-with-zeek
---

# Hunting For Dns Tunneling With Zeek (cold-box)

> **Journal ID:** `CB-SKL-233` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-233`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-dns-tunneling-with-zeek")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-dns-tunneling-with-zeek")` → note **`CB-SKL-233`**
2. `log_skill(case_id, journal_id="CB-SKL-233", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-233` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for data exfiltration over DNS covert channels
- After threat intelligence indicates DNS-based C2 frameworks targeting your industry
- When dns.log shows unusually high query volumes to specific domains
- During investigation of suspected data theft where no HTTP/S exfiltration is found
- When monitoring for tools like iodine, dnscat2, DNSExfiltrator, or DNS-over-HTTPS tunneling

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `strings` | `SIFT-044` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |
| `zeek` | `SIFT-119` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-233] strings per playbook step",
  "why": "Executing cb-hunting-for-dns-tunneling-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-233] sort per playbook step",
  "why": "Executing cb-hunting-for-dns-tunneling-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-233] zeek per playbook step",
  "why": "Executing cb-hunting-for-dns-tunneling-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-233` (`cb-hunting-for-dns-tunneling-with-zeek`)

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

- When hunting for data exfiltration over DNS covert channels
- After threat intelligence indicates DNS-based C2 frameworks targeting your industry
- When dns.log shows unusually high query volumes to specific domains
- During investigation of suspected data theft where no HTTP/S exfiltration is found
- When monitoring for tools like iodine, dnscat2, DNSExfiltrator, or DNS-over-HTTPS tunneling

## Prerequisites

- Zeek deployed on network tap or SPAN port capturing DNS traffic
- Zeek dns.log with full query and response fields
- SIEM platform for dns.log analysis (Splunk, Elastic)
- RITA (Real Intelligence Threat Analytics) for automated DNS analysis
- Passive DNS data for historical domain resolution context

## Workflow

1. **Analyze Query Length Distribution**: DNS tunneling encodes data in subdomain labels, producing queries significantly longer than normal. Normal DNS queries average 20-30 characters; tunneling queries often exceed 50+ characters. Calculate mean and standard deviation of query lengths per domain.
2. **Calculate Subdomain Entropy**: Tunneling encodes data using Base32/Base64, producing high-entropy subdomain strings. Calculate Shannon entropy of subdomain labels -- values above 3.5 bits/character strongly suggest encoded data.
3. **Count Unique Subdomains Per Domain**: Legitimate domains have relatively few unique subdomains. DNS tunneling generates hundreds or thousands of unique subdomains under a single parent domain.
4. **Monitor DNS Record Type Distribution**: TXT, NULL, CNAME, and MX records can carry more data than A records. Excessive TXT queries to a single domain indicate data transfer via DNS.
5. **Detect High Query Volume**: Flag domains receiving more than 100 queries per hour from a single source, especially when combined with high subdomain uniqueness.
6. **Analyze Query Timing**: DNS tunneling tools produce regular query patterns (beaconing) or burst patterns (data transfer). Apply frequency analysis to DNS query timestamps.
7. **Cross-Reference with conn.log**: Correlate DNS queries with connection metadata to identify the process or endpoint generating suspicious queries.
8. **Validate with Domain Intelligence**: Check suspicious domains against WHOIS data, certificate transparency, and threat intelligence feeds.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1071.004 | Application Layer Protocol: DNS |
| T1048.003 | Exfiltration Over Alternative Protocol: DNS |
| T1572 | Protocol Tunneling |
| Shannon Entropy | Measure of randomness in subdomain strings |
| Zeek dns.log | DNS query/response metadata |
| RITA | Automated DNS tunneling detection from Zeek logs |
| iodine | IPv4-over-DNS tunneling tool |
| dnscat2 | DNS-based command-and-control tool |
| DNSExfiltrator | Data exfiltration tool using DNS requests |

## Detection Queries

### Zeek Script -- DNS Tunnel Detection
```zeek
@load base/protocols/dns
module DNSTunnel;

export {
    redef enum Notice::Type += { DNSTunnel::Long_DNS_Query };
    const query_length_threshold = 50 &redef;
    const query_count_threshold = 100 &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( |query| > query_length_threshold ) {
        NOTICE([$note=DNSTunnel::Long_DNS_Query,
                $msg=fmt("Long DNS query detected: %s (%d chars)", query, |query|),
                $conn=c]);
    }
}
```

### Splunk -- DNS Tunneling Indicators from Zeek
```spl
index=zeek sourcetype=bro_dns
| rex field=query "(?<subdomain>[^.]+)\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count dc(subdomain) as unique_subs avg(len(query)) as avg_len max(len(query)) as max_len by src basedomain
| where count > 100 AND (unique_subs > 50 OR avg_len > 40)
| sort -unique_subs
```

### Splunk -- High Entropy Subdomain Detection
```spl
index=zeek sourcetype=bro_dns
| rex field=query "^(?<subdomain>[^.]+)"
| where len(subdomain) > 20
| eval char_count=len(subdomain)
| stats count dc(query) as unique_queries avg(char_count) as avg_sub_len by src query_type_name basedomain
| where unique_queries > 30 AND avg_sub_len > 25
| sort -unique_queries
```

### RITA Analysis
```bash
rita import /path/to/zeek/logs dataset_name
rita show-dns-fqdn-ips-long dataset_name
rita show-exploded-dns dataset_name
rita show-dns-tunneling dataset_name --csv > dns_tunnel_results.csv
```

## Common Scenarios

1. **dnscat2 C2**: Encodes command-and-control traffic in DNS CNAME/TXT queries with Base64-encoded subdomain labels. Produces high query volumes with long, high-entropy subdomains.
2. **iodine IPv4 Tunnel**: Creates a virtual network interface tunneling all IP traffic through DNS. Generates massive DNS query volumes with NULL record types.
3. **Data Exfiltration via DNS**: Sensitive data encoded in subdomain labels (e.g., `aGVsbG8gd29ybGQ.exfil.attacker.com`), sent as A or TXT queries. Each query carries ~63 bytes of data.
4. **DNS-over-HTTPS Tunneling**: Bypasses traditional DNS monitoring by sending DNS queries over HTTPS to public resolvers (8.8.8.8, 1.1.1.1), requiring TLS inspection for detection.
5. **Cobalt Strike DNS Beacon**: Uses DNS A/TXT records for C2 communication with configurable subdomain encoding schemes.

## Output Format

```
Hunt ID: TH-DNSTUNNEL-[DATE]-[SEQ]
Source IP: [Internal IP]
Source Host: [Hostname]
Target Domain: [Base domain]
Query Count: [Total queries in window]
Unique Subdomains: [Count]
Avg Query Length: [Characters]
Max Query Length: [Characters]
Subdomain Entropy: [Bits per character]
Primary Record Type: [A/TXT/CNAME/NULL]
Data Volume Estimate: [Bytes exfiltrated]
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
