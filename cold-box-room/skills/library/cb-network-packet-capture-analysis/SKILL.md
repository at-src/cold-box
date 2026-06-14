---
name: cb-network-packet-capture-analysis
skill_id: cb-network-packet-capture-analysis
journal_id: CB-SKL-091
description: Cold-box analyst playbook — Network Packet Capture Analysis. Perform
  forensic analysis of network packet captures (PCAP/PCAPNG) using Wireshark, tshark,
  and tcpdump to reconstruct network communications, extract transferred files, identify
  malicious traffic, and establish evidence of data exfiltratio
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- network_pcap
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- pcap
- wireshark
- tshark
- tcpdump
- network-forensics
- packet-capture
- protocol-analysis
- traffic-analysis
- pcapng
- network-evidence
cold_box_version: 2
inspired_by: performing-network-packet-capture-analysis
---

# Network Packet Capture Analysis (cold-box)

> **Journal ID:** `CB-SKL-091` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-091`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-network-packet-capture-analysis")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-network-packet-capture-analysis")` → note **`CB-SKL-091`**
2. `log_skill(case_id, journal_id="CB-SKL-091", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-091` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing network packet capture analysis
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `wireshark` | `SIFT-118` | no | yes |
| `tcpdump` | `SIFT-116` | no | yes |
| `tshark` | `SIFT-117` | no | no |
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `wireshark` → `SIFT-118`

```json
{
  "tool_id": "SIFT-118",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-091] wireshark per playbook step",
  "why": "Executing cb-network-packet-capture-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `tcpdump` → `SIFT-116`

```json
{
  "tool_id": "SIFT-116",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-091] tcpdump per playbook step",
  "why": "Executing cb-network-packet-capture-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `tshark` → `SIFT-117`

```json
{
  "tool_id": "SIFT-117",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-091] tshark per playbook step",
  "why": "Executing cb-network-packet-capture-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-091] sort per playbook step",
  "why": "Executing cb-network-packet-capture-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-091] file per playbook step",
  "why": "Executing cb-network-packet-capture-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-091` (`cb-network-packet-capture-analysis`)

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

Network packet captures (PCAP/PCAPNG files) represent the ultimate source of truth about network activity and provide irrefutable evidence of communications between hosts. PCAP files log every packet transmitted over a network segment, making them vital for forensic investigations involving data exfiltration, command-and-control communications, lateral movement, malware delivery, and unauthorized access. Wireshark is the primary tool for interactive analysis, while tshark provides command-line capabilities for automated processing and scripting. Modern PCAPNG format supports additional metadata including interface descriptions, capture comments, precise timestamps, and per-packet annotations.


## When to Use

- When conducting security assessments that involve performing network packet capture analysis
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Wireshark 4.x with protocol dissectors
- tshark command-line tool (included with Wireshark)
- tcpdump for capture and basic filtering
- Python 3.8+ with scapy and pyshark libraries
- Sufficient disk space for PCAP files (can be multi-GB)

## Capture Techniques

### tcpdump

```bash
# Capture all traffic on interface eth0
tcpdump -i eth0 -w capture.pcap

# Capture with rotation (100MB files, keep 10)
tcpdump -i eth0 -w capture_%Y%m%d_%H%M%S.pcap -C 100 -W 10

# Capture specific host traffic
tcpdump -i eth0 host 192.168.1.100 -w host_traffic.pcap

# Capture specific port traffic
tcpdump -i eth0 port 443 -w https_traffic.pcap

# Capture with BPF filter for suspicious ports
tcpdump -i eth0 'port 4444 or port 8080 or port 1337' -w suspicious.pcap
```

### Wireshark Display Filters

```
# HTTP traffic
http

# DNS queries
dns

# SMB file transfers
smb2

# Specific IP communication
ip.addr == 192.168.1.100

# Failed TCP connections
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Large data transfers (potential exfiltration)
tcp.len > 1000

# Specific protocol by port
tcp.port == 4444

# TLS handshakes (SNI extraction)
tls.handshake.type == 1

# HTTP POST requests
http.request.method == "POST"

# DNS queries to suspicious TLDs
dns.qry.name contains ".xyz" or dns.qry.name contains ".top"

# Beaconing detection (regular intervals)
frame.time_delta_displayed > 55 && frame.time_delta_displayed < 65
```

### tshark Analysis Commands

```bash
# Extract HTTP URLs from capture
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

# Extract file transfers (HTTP objects)
tshark -r capture.pcap --export-objects http,exported_files/

# Extract SMB file transfers
tshark -r capture.pcap --export-objects smb,smb_files/

# Protocol hierarchy statistics
tshark -r capture.pcap -z io,phs

# Conversation statistics
tshark -r capture.pcap -z conv,tcp

# Extract TLS SNI (Server Name Indication)
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

# Top talkers by bytes
tshark -r capture.pcap -z endpoints,ip -q

# Extract credentials (FTP, HTTP Basic)
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS || http.authorization" -T fields -e ftp.request.arg -e http.authorization
```

## Python PCAP Analysis

```python
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
import os
import sys
import json
from collections import defaultdict, Counter
from datetime import datetime


class PCAPForensicAnalyzer:
    """Forensic analysis of PCAP files using Scapy."""

    def __init__(self, pcap_path: str, output_dir: str):
        self.pcap_path = pcap_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.packets = rdpcap(pcap_path)

    def get_conversations(self) -> list:
        """Extract unique IP conversations with byte counts."""
        convos = defaultdict(lambda: {"packets": 0, "bytes": 0})
        for pkt in self.packets:
            if IP in pkt:
                key = tuple(sorted([pkt[IP].src, pkt[IP].dst]))
                convos[key]["packets"] += 1
                convos[key]["bytes"] += len(pkt)

        return [
            {"src": k[0], "dst": k[1], "packets": v["packets"], "bytes": v["bytes"]}
            for k, v in sorted(convos.items(), key=lambda x: x[1]["bytes"], reverse=True)
        ]

    def extract_dns_queries(self) -> list:
        """Extract all DNS queries from the capture."""
        queries = []
        for pkt in self.packets:
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                queries.append({
                    "query": pkt[DNSQR].qname.decode(errors="replace").rstrip("."),
                    "type": pkt[DNSQR].qtype,
                    "src": pkt[IP].src if IP in pkt else "unknown"
                })
        return queries

    def detect_beaconing(self, threshold_seconds: float = 5.0) -> list:
        """Detect potential beaconing activity based on regular intervals."""
        ip_timestamps = defaultdict(list)
        for pkt in self.packets:
            if IP in pkt and TCP in pkt:
                key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                ip_timestamps[key].append(float(pkt.time))

        beacons = []
        for key, times in ip_timestamps.items():
            if len(times) < 5:
                continue
            deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
            if deltas:
                avg_delta = sum(deltas) / len(deltas)
                variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
                if variance < threshold_seconds and avg_delta > 1:
                    beacons.append({
                        "src": key[0], "dst": key[1], "port": key[2],
                        "avg_interval": round(avg_delta, 2),
                        "variance": round(variance, 4),
                        "connection_count": len(times)
                    })
        return sorted(beacons, key=lambda x: x["variance"])

    def get_protocol_distribution(self) -> dict:
        """Get protocol distribution statistics."""
        protocols = Counter()
        for pkt in self.packets:
            if TCP in pkt:
                protocols[f"TCP/{pkt[TCP].dport}"] += 1
            elif UDP in pkt:
                protocols[f"UDP/{pkt[UDP].dport}"] += 1
        return dict(protocols.most_common(50))

    def generate_report(self) -> str:
        """Generate comprehensive PCAP analysis report."""
        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "pcap_file": self.pcap_path,
            "total_packets": len(self.packets),
            "conversations": self.get_conversations()[:50],
            "dns_queries": self.extract_dns_queries()[:200],
            "potential_beacons": self.detect_beaconing(),
            "protocol_distribution": self.get_protocol_distribution()
        }

        report_path = os.path.join(self.output_dir, "pcap_forensic_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[*] Total packets: {report['total_packets']}")
        print(f"[*] Conversations: {len(report['conversations'])}")
        print(f"[*] DNS queries: {len(report['dns_queries'])}")
        print(f"[*] Potential beacons: {len(report['potential_beacons'])}")
        return report_path


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <pcap_file> <output_dir>")
        sys.exit(1)
    analyzer = PCAPForensicAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.generate_report()


if __name__ == "__main__":
    main()
```

## References

- Wireshark Documentation: https://www.wireshark.org/docs/
- PCAP Analysis Mastery: https://insanecyber.com/mastering-pcap-review/
- SANS Network Forensics: https://www.sans.org/cyber-security-courses/network-forensics/
- Public PCAPs for Practice: https://www.netresec.com/?page=PcapFiles

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
