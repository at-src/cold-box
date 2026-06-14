---
name: cb-detecting-dns-exfiltration-with-dns-query-analysis
skill_id: cb-detecting-dns-exfiltration-with-dns-query-analysis
journal_id: CB-SKL-183
description: Cold-box analyst playbook — Detecting Dns Exfiltration With Dns Query
  Analysis. Detect data exfiltration through DNS tunneling by analyzing query entropy,
  subdomain length, query volume, TXT record abuse, and response payload sizes using
  passive DNS monitoring.
domain: cold-box
subdomain: network-security
tier: adjacent
case_profiles:
- network_pcap
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- dns-exfiltration
- dns-tunneling
- data-exfiltration
- threat-detection
- entropy-analysis
- passive-dns
- network-monitoring
- iodine
- dnscat2
cold_box_version: 2
inspired_by: detecting-dns-exfiltration-with-dns-query-analysis
---

# Detecting Dns Exfiltration With Dns Query Analysis (cold-box)

> **Journal ID:** `CB-SKL-183` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-183`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-dns-exfiltration-with-dns-query-analysis")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-dns-exfiltration-with-dns-query-analysis")` → note **`CB-SKL-183`**
2. `log_skill(case_id, journal_id="CB-SKL-183", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-183` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting dns exfiltration with dns query analysis
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `strings` | `SIFT-044` | yes | yes |
| `tcpdump` | `SIFT-116` | no | yes |
| `sort` | `SIFT-020` | yes | yes |
| `zeek` | `SIFT-119` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-183] strings per playbook step",
  "why": "Executing cb-detecting-dns-exfiltration-with-dns-query-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `tcpdump` → `SIFT-116`

```json
{
  "tool_id": "SIFT-116",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-183] tcpdump per playbook step",
  "why": "Executing cb-detecting-dns-exfiltration-with-dns-query-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-183] sort per playbook step",
  "why": "Executing cb-detecting-dns-exfiltration-with-dns-query-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-183] zeek per playbook step",
  "why": "Executing cb-detecting-dns-exfiltration-with-dns-query-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-183] file per playbook step",
  "why": "Executing cb-detecting-dns-exfiltration-with-dns-query-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-183` (`cb-detecting-dns-exfiltration-with-dns-query-analysis`)

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

DNS exfiltration exploits the Domain Name System as a covert channel to extract data from compromised networks. Attackers encode stolen data into DNS query names (subdomains) or DNS response records (TXT, CNAME, NULL), bypassing traditional security controls that typically allow DNS traffic unrestricted. Tools like iodine, dnscat2, and dns2tcp enable full TCP tunneling over DNS. Detection requires analyzing DNS query patterns for anomalies including excessive query length, high entropy subdomain strings, abnormal query volumes to single domains, and oversized TXT record responses. This skill covers building a comprehensive DNS exfiltration detection capability using passive DNS analysis, statistical methods, and machine learning approaches.


## When to Use

- When investigating security incidents that require detecting dns exfiltration with dns query analysis
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Access to DNS query logs (passive DNS capture, DNS server logs, or PCAP)
- Zeek, Suricata, or tcpdump for DNS traffic capture
- Python 3.8+ with scipy, numpy, pandas, and scikit-learn
- SIEM platform for alert correlation
- Baseline of normal DNS traffic patterns for the environment

## Core Concepts

### DNS Tunneling Mechanics

DNS exfiltration encodes data in different parts of DNS messages:

**Outbound (Query-based exfiltration):**
```
Encoded data as subdomain labels:
dGhlIHNlY3JldCBkYXRh.exfil.attacker.com
[base64-encoded data].[tunnel domain]

Query types used: A, AAAA, CNAME, MX, TXT, NULL
```

**Inbound (Response-based command channel):**
```
TXT records carry encoded commands/data in responses
CNAME records chain encoded data through multiple labels
NULL records carry arbitrary binary data
```

### Detection Indicators

| Indicator | Normal DNS | DNS Tunneling |
|-----------|-----------|---------------|
| Subdomain length | 5-20 chars | 40-253 chars |
| Label count | 2-4 labels | 5-10+ labels |
| Shannon entropy | 2.5-3.5 bits | 4.0-5.5 bits |
| Query volume (per domain) | Variable | 100s-1000s/min |
| TXT response size | < 100 bytes | 200-4000+ bytes |
| Unique subdomains | Low | Very high |
| Query type distribution | Mostly A/AAAA | Heavy TXT, NULL, CNAME |

### Common Tunneling Tools

| Tool | Protocol | Encoding | Detection Difficulty |
|------|----------|----------|---------------------|
| iodine | IP-over-DNS | Base32/Base64/Raw | Medium |
| dnscat2 | TCP-over-DNS | Hex encoding | Medium |
| dns2tcp | TCP-over-DNS | Base64 | Medium |
| DNSExfiltrator | Custom | Base64 | Low |
| Cobalt Strike DNS | C2 over DNS | Custom encoding | High |

## Workflow

### Step 1: Capture DNS Traffic

**Using Zeek:**
```bash
# Live capture
zeek -i eth0 -C base/protocols/dns

# Offline PCAP analysis
zeek -r traffic.pcap base/protocols/dns

# Output: dns.log with query, qtype, answers, TTL
```

**Using tcpdump:**
```bash
# Capture all DNS traffic
tcpdump -i eth0 -w dns_capture.pcap port 53

# Capture with size filter (large DNS packets)
tcpdump -i eth0 -w large_dns.pcap 'port 53 and greater 512'
```

**Using Suricata:**
```yaml
# In suricata.yaml, enable DNS logging
outputs:
  - eve-log:
      types:
        - dns:
            query: yes
            answer: yes
            formats: [detailed]
```

### Step 2: Analyze Query Characteristics

Python script for DNS exfiltration detection:

```python
#!/usr/bin/env python3
"""DNS Exfiltration Detector - Analyzes DNS logs for tunneling indicators."""

import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

import pandas as pd


def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not domain:
        return 0.0
    freq = defaultdict(int)
    for char in domain:
        freq[char] += 1
    length = len(domain)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy


def extract_subdomain(query: str) -> str:
    """Extract subdomain portion from FQDN."""
    parts = query.rstrip('.').split('.')
    if len(parts) > 2:
        return '.'.join(parts[:-2])
    return ''


def get_base_domain(query: str) -> str:
    """Extract registered domain from FQDN."""
    parts = query.rstrip('.').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return query


def is_base64_like(s: str) -> bool:
    """Check if string resembles base64 encoding."""
    b64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    if len(s) < 10:
        return False
    char_ratio = sum(1 for c in s if c in b64_chars) / len(s)
    return char_ratio > 0.9 and calculate_entropy(s) > 4.0


def is_hex_encoded(s: str) -> bool:
    """Check if string appears hex-encoded."""
    hex_chars = set('0123456789abcdefABCDEF')
    if len(s) < 16:
        return False
    clean = s.replace('.', '').replace('-', '')
    return all(c in hex_chars for c in clean) and len(clean) % 2 == 0


class DNSExfiltrationDetector:
    def __init__(self):
        self.domain_stats = defaultdict(lambda: {
            'query_count': 0,
            'unique_subdomains': set(),
            'total_subdomain_length': 0,
            'entropy_sum': 0.0,
            'query_types': defaultdict(int),
            'source_ips': set(),
            'first_seen': None,
            'last_seen': None,
            'txt_response_sizes': [],
        })

        # Detection thresholds
        self.thresholds = {
            'min_query_count': 50,
            'min_unique_subdomains': 30,
            'avg_subdomain_length': 30,
            'avg_entropy': 3.8,
            'unique_ratio': 0.7,
            'txt_query_ratio': 0.3,
            'max_label_length': 63,
            'max_subdomain_labels': 5,
        }

    def process_query(self, timestamp, src_ip, query, qtype, response_size=0):
        """Process a single DNS query and update statistics."""
        base_domain = get_base_domain(query)
        subdomain = extract_subdomain(query)

        stats = self.domain_stats[base_domain]
        stats['query_count'] += 1
        stats['unique_subdomains'].add(subdomain)
        stats['total_subdomain_length'] += len(subdomain)
        stats['entropy_sum'] += calculate_entropy(subdomain)
        stats['query_types'][qtype] += 1
        stats['source_ips'].add(src_ip)

        if stats['first_seen'] is None:
            stats['first_seen'] = timestamp
        stats['last_seen'] = timestamp

        if qtype in ('TXT', 'NULL') and response_size > 0:
            stats['txt_response_sizes'].append(response_size)

    def analyze(self):
        """Analyze accumulated statistics and return suspicious domains."""
        alerts = []

        for domain, stats in self.domain_stats.items():
            if stats['query_count'] < self.thresholds['min_query_count']:
                continue

            unique_count = len(stats['unique_subdomains'])
            avg_length = stats['total_subdomain_length'] / stats['query_count']
            avg_entropy = stats['entropy_sum'] / stats['query_count']
            unique_ratio = unique_count / stats['query_count']

            txt_queries = stats['query_types'].get('TXT', 0) + stats['query_types'].get('NULL', 0)
            txt_ratio = txt_queries / stats['query_count']

            score = 0
            indicators = []

            if avg_length > self.thresholds['avg_subdomain_length']:
                score += 25
                indicators.append(f"high_avg_subdomain_length={avg_length:.1f}")

            if avg_entropy > self.thresholds['avg_entropy']:
                score += 25
                indicators.append(f"high_entropy={avg_entropy:.2f}")

            if unique_ratio > self.thresholds['unique_ratio']:
                score += 20
                indicators.append(f"high_unique_ratio={unique_ratio:.2f}")

            if txt_ratio > self.thresholds['txt_query_ratio']:
                score += 15
                indicators.append(f"high_txt_ratio={txt_ratio:.2f}")

            if unique_count > self.thresholds['min_unique_subdomains']:
                score += 15
                indicators.append(f"unique_subdomains={unique_count}")

            # Check for encoding patterns
            encoded_count = sum(
                1 for sd in list(stats['unique_subdomains'])[:100]
                if is_base64_like(sd) or is_hex_encoded(sd)
            )
            if encoded_count > 20:
                score += 20
                indicators.append(f"encoded_subdomains={encoded_count}")

            if score >= 50:
                duration = (stats['last_seen'] - stats['first_seen']).total_seconds() if stats['first_seen'] and stats['last_seen'] else 0
                alerts.append({
                    'domain': domain,
                    'score': min(score, 100),
                    'query_count': stats['query_count'],
                    'unique_subdomains': unique_count,
                    'avg_subdomain_length': round(avg_length, 1),
                    'avg_entropy': round(avg_entropy, 2),
                    'unique_ratio': round(unique_ratio, 2),
                    'txt_ratio': round(txt_ratio, 2),
                    'source_ips': list(stats['source_ips']),
                    'duration_seconds': duration,
                    'indicators': indicators,
                })

        return sorted(alerts, key=lambda x: x['score'], reverse=True)

    def process_zeek_dns_log(self, log_path):
        """Process Zeek dns.log file."""
        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                fields = line.strip().split('\t')
                if len(fields) < 22:
                    continue
                try:
                    ts = datetime.fromtimestamp(float(fields[0]))
                    src_ip = fields[2]
                    query = fields[9]
                    qtype = fields[11]
                    self.process_query(ts, src_ip, query, qtype)
                except (ValueError, IndexError):
                    continue

    def process_eve_json(self, log_path):
        """Process Suricata EVE JSON DNS log."""
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') != 'dns':
                        continue
                    dns = event.get('dns', {})
                    ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    src_ip = event.get('src_ip', '')
                    query = dns.get('rrname', '')
                    qtype = dns.get('rrtype', '')
                    self.process_query(ts, src_ip, query, qtype)
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue


def main():
    detector = DNSExfiltrationDetector()

    log_file = sys.argv[1] if len(sys.argv) > 1 else '/opt/zeek/logs/current/dns.log'

    if log_file.endswith('.json'):
        detector.process_eve_json(log_file)
    else:
        detector.process_zeek_dns_log(log_file)

    alerts = detector.analyze()

    if alerts:
        print(f"\n{'='*80}")
        print(f"DNS EXFILTRATION DETECTION RESULTS - {len(alerts)} suspicious domains found")
        print(f"{'='*80}\n")

        for alert in alerts:
            severity = "CRITICAL" if alert['score'] >= 80 else "HIGH" if alert['score'] >= 60 else "MEDIUM"
            print(f"[{severity}] Domain: {alert['domain']}")
            print(f"  Score: {alert['score']}/100")
            print(f"  Queries: {alert['query_count']}, Unique Subdomains: {alert['unique_subdomains']}")
            print(f"  Avg Subdomain Length: {alert['avg_subdomain_length']}, Avg Entropy: {alert['avg_entropy']}")
            print(f"  Source IPs: {', '.join(alert['source_ips'][:5])}")
            print(f"  Indicators: {', '.join(alert['indicators'])}")
            print()
    else:
        print("No DNS exfiltration indicators detected.")


if __name__ == '__main__':
    main()
```

### Step 3: Deploy Suricata Rules for DNS Exfiltration

```
# Detect long DNS queries (potential tunneling)
alert dns $HOME_NET any -> any 53 (msg:"DNS Exfiltration - Excessive query length"; dns.query; content:"."; pcre:"/^.{60,}/"; threshold:type both,track by_src,count 20,seconds 60; classtype:bad-unknown; sid:3000001; rev:1;)

# Detect high-entropy DNS subdomain
alert dns $HOME_NET any -> any 53 (msg:"DNS Exfiltration - High entropy subdomain"; dns.query; pcre:"/^[a-zA-Z0-9+\/=]{30,}\./"; threshold:type both,track by_src,count 10,seconds 60; classtype:bad-unknown; sid:3000002; rev:1;)

# Detect large TXT record responses
alert dns any 53 -> $HOME_NET any (msg:"DNS Exfiltration - Large TXT response"; content:"|00 10|"; byte_test:2,>,400,0,relative; classtype:bad-unknown; sid:3000003; rev:1;)

# Detect NULL record queries (used by iodine)
alert dns $HOME_NET any -> any 53 (msg:"DNS Exfiltration - NULL record query (iodine indicator)"; content:"|00 0a|"; classtype:bad-unknown; sid:3000004; rev:1;)

# Detect dnscat2 traffic pattern
alert dns $HOME_NET any -> any 53 (msg:"DNS Exfiltration - dnscat2 indicator"; dns.query; content:"dnscat"; nocase; classtype:trojan-activity; sid:3000005; rev:1;)
```

### Step 4: SIEM Detection Rules

**Splunk SPL query for DNS exfiltration:**

```spl
index=dns sourcetype=zeek:dns
| eval subdomain=mvindex(split(query,"."),0)
| eval subdomain_len=len(subdomain)
| eval label_count=mvcount(split(query,"."))
| stats count as query_count,
        dc(subdomain) as unique_subdomains,
        avg(subdomain_len) as avg_sub_len,
        values(src_ip) as source_ips
        by query_domain
| where query_count > 100 AND avg_sub_len > 30 AND unique_subdomains > 50
| eval risk_score = case(
    avg_sub_len > 50 AND unique_subdomains > 200, "Critical",
    avg_sub_len > 40 AND unique_subdomains > 100, "High",
    avg_sub_len > 30 AND unique_subdomains > 50, "Medium",
    true(), "Low")
| sort -query_count
| table query_domain risk_score query_count unique_subdomains avg_sub_len source_ips
```

## Response Actions

1. **Block the tunnel domain** at DNS resolver and firewall level
2. **Isolate the source host** from the network for forensic investigation
3. **Capture full PCAP** of the DNS traffic for evidence preservation
4. **Identify exfiltrated data** by decoding captured DNS queries
5. **Check for persistence** mechanisms on the compromised host
6. **Update blocklists** with identified C2 domains and infrastructure

## Best Practices

- **DNS Logging** - Enable full DNS query and response logging at resolvers and network level
- **Internal DNS Only** - Force all DNS through internal resolvers; block direct external DNS (port 53)
- **Response Policy Zones** - Deploy RPZ feeds to block known tunneling domains
- **Baseline First** - Establish normal DNS query patterns before setting detection thresholds
- **TXT Record Monitoring** - Pay special attention to TXT and NULL record queries
- **Encrypted DNS Awareness** - Monitor for DoH/DoT usage that may bypass DNS inspection

## References

- [Splunk DNS Exfiltration Detection with Deep Learning](https://www.splunk.com/en_us/blog/security/machine-learning-in-security-detect-dns-data-exfiltration-using-deep-learning.html)
- [Akamai DNS Data Exfiltration](https://www.akamai.com/glossary/what-is-dns-data-exfiltration)
- [SANS Detecting DNS Tunneling](https://www.giac.org/paper/gcia/1116/detecting-dns-tunneling/108367)
- [Fidelis DNS Tunneling Detection](https://fidelissecurity.com/threatgeek/learn/dns-tunneling-detection/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
