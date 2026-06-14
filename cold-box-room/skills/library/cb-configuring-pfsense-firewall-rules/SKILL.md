---
name: cb-configuring-pfsense-firewall-rules
skill_id: cb-configuring-pfsense-firewall-rules
journal_id: CB-SKL-158
description: Cold-box analyst playbook — Configuring Pfsense Firewall Rules. Configures
  pfSense firewall rules, NAT policies, VPN tunnels, and traffic shaping to enforce
  network segmentation, control traffic flow, and protect internal network zones in
  enterprise and small-to-medium business environments.
domain: cold-box
subdomain: network-security
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- network-security
- pfsense
- firewall
- nat
- network-segmentation
cold_box_version: 2
inspired_by: configuring-pfsense-firewall-rules
---

# Configuring Pfsense Firewall Rules (cold-box)

> **Journal ID:** `CB-SKL-158` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-158`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-configuring-pfsense-firewall-rules")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-configuring-pfsense-firewall-rules")` → note **`CB-SKL-158`**
2. `log_skill(case_id, journal_id="CB-SKL-158", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-158` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Deploying a perimeter or internal firewall to segment and protect network zones (DMZ, internal, guest, IoT)
- Creating granular access control rules to restrict traffic between VLANs and network segments
- Configuring NAT rules for port forwarding to internal services exposed to the internet
- Setting up site-to-site or remote access VPN tunnels using IPsec or OpenVPN
- Implementing traffic shaping and bandwidth management for quality-of-service requirements

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-158] file per playbook step",
  "why": "Executing cb-configuring-pfsense-firewall-rules \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-158` (`cb-configuring-pfsense-firewall-rules`)

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

- Deploying a perimeter or internal firewall to segment and protect network zones (DMZ, internal, guest, IoT)
- Creating granular access control rules to restrict traffic between VLANs and network segments
- Configuring NAT rules for port forwarding to internal services exposed to the internet
- Setting up site-to-site or remote access VPN tunnels using IPsec or OpenVPN
- Implementing traffic shaping and bandwidth management for quality-of-service requirements

**Do not use** as a substitute for host-based firewalls on individual systems, for SSL/TLS deep packet inspection without dedicated hardware acceleration, or as the sole security control without complementary IDS/IPS.

## Prerequisites

- pfSense 2.7+ installed on dedicated hardware or virtual machine with at least two network interfaces
- Access to the pfSense WebConfigurator (default: https://192.168.1.1)
- Network topology diagram showing all interfaces, VLANs, and desired traffic flow
- DNS and DHCP configuration planned for each network zone
- Understanding of TCP/IP, NAT, and stateful firewall concepts

## Workflow

### Step 1: Configure Network Interfaces and VLANs

Access the pfSense WebConfigurator and define interfaces:

```
Navigate: Interfaces > Assignments

WAN Interface (igb0):
  - Type: DHCP or Static IP from ISP
  - Block private networks: Enabled
  - Block bogon networks: Enabled

LAN Interface (igb1):
  - IPv4: 10.10.1.1/24
  - Description: CORPORATE_LAN

Create VLANs:
  Navigate: Interfaces > VLANs > Add
  - VLAN 10 on igb1: DMZ (10.10.10.1/24)
  - VLAN 20 on igb1: SERVERS (10.10.20.1/24)
  - VLAN 30 on igb1: GUEST (10.10.30.1/24)
  - VLAN 40 on igb1: IOT (10.10.40.1/24)

Assign VLANs:
  Navigate: Interfaces > Assignments > Add each VLAN
  Enable each interface and assign the gateway IP
```

### Step 2: Configure DHCP and DNS for Each Zone

```
Navigate: Services > DHCP Server

CORPORATE_LAN (10.10.1.0/24):
  Range: 10.10.1.100 - 10.10.1.200
  DNS: 10.10.20.10 (internal DNS server)
  Gateway: 10.10.1.1

DMZ (10.10.10.0/24):
  Range: 10.10.10.100 - 10.10.10.200
  DNS: 10.10.20.10
  Gateway: 10.10.10.1

GUEST (10.10.30.0/24):
  Range: 10.10.30.100 - 10.10.30.200
  DNS: 1.1.1.1, 8.8.8.8 (public DNS only)
  Gateway: 10.10.30.1

Navigate: Services > DNS Resolver
  Enable DNS Resolver on all interfaces except GUEST
  Enable DNSSEC
  Configure forwarding to upstream DNS servers
```

### Step 3: Create Firewall Rule Aliases

```
Navigate: Firewall > Aliases

RFC1918_Networks:
  Type: Network
  Values: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

WebPorts:
  Type: Port
  Values: 80, 443

ManagementPorts:
  Type: Port
  Values: 22, 3389, 5900

CriticalServers:
  Type: Host
  Values: 10.10.20.10, 10.10.20.11, 10.10.20.12

BlockedCountries:
  Type: URL Table
  URL: https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
  Update: 24 hours
```

### Step 4: Implement Firewall Rules by Zone

```
Navigate: Firewall > Rules

=== WAN Rules ===
# Block all inbound by default (implicit deny)
# Allow established/related traffic (automatic in pfSense stateful mode)

# Allow inbound to DMZ web server (via NAT)
Action: Pass | Interface: WAN | Protocol: TCP
Source: any | Destination: WAN Address | Port: 80, 443
Description: Allow HTTP/HTTPS to DMZ web server

=== LAN Rules ===
# Allow LAN to access internal servers
Action: Pass | Interface: LAN | Protocol: TCP
Source: LAN net | Destination: SERVERS net | Port: WebPorts, 3306, 5432
Description: Allow LAN to internal web and database servers

# Allow LAN to internet
Action: Pass | Interface: LAN | Protocol: any
Source: LAN net | Destination: ! RFC1918_Networks
Description: Allow LAN to internet (block inter-VLAN via RFC1918 exclusion)

# Block LAN to IoT (explicit deny before implicit allow)
Action: Block | Interface: LAN | Protocol: any
Source: LAN net | Destination: IOT net
Description: Block direct LAN to IoT communication

=== DMZ Rules ===
# Allow DMZ web servers to query internal DNS
Action: Pass | Interface: DMZ | Protocol: TCP/UDP
Source: DMZ net | Destination: 10.10.20.10 | Port: 53
Description: Allow DMZ DNS queries to internal resolver

# Allow DMZ to internet for updates only
Action: Pass | Interface: DMZ | Protocol: TCP
Source: DMZ net | Destination: any | Port: 80, 443
Description: Allow DMZ outbound HTTP/HTTPS for updates

# Block all other DMZ traffic
Action: Block | Interface: DMZ | Protocol: any
Source: DMZ net | Destination: any
Description: Default deny for DMZ

=== GUEST Rules ===
# Allow guest to internet only (DNS and web)
Action: Pass | Interface: GUEST | Protocol: TCP/UDP
Source: GUEST net | Destination: ! RFC1918_Networks | Port: 53, 80, 443
Description: Allow guest internet access only

# Block all guest to internal
Action: Block | Interface: GUEST | Protocol: any
Source: GUEST net | Destination: RFC1918_Networks
Description: Block guest access to all internal networks

=== IOT Rules ===
# Allow IoT to specific cloud endpoints
Action: Pass | Interface: IOT | Protocol: TCP
Source: IOT net | Destination: ! RFC1918_Networks | Port: 443, 8883
Description: Allow IoT HTTPS and MQTT to cloud

# Block IoT inter-device communication
Action: Block | Interface: IOT | Protocol: any
Source: IOT net | Destination: IOT net
Description: Prevent IoT lateral movement

# Block IoT to all internal networks
Action: Block | Interface: IOT | Protocol: any
Source: IOT net | Destination: RFC1918_Networks
Description: Block IoT access to internal
```

### Step 5: Configure NAT Rules

```
Navigate: Firewall > NAT > Port Forward

# Web server in DMZ
Interface: WAN | Protocol: TCP
Destination: WAN address | Port: 443
Redirect target IP: 10.10.10.50 | Port: 443
NAT Reflection: Enable
Description: HTTPS to DMZ web server

# SSH jump host (non-standard port)
Interface: WAN | Protocol: TCP
Destination: WAN address | Port: 2222
Redirect target IP: 10.10.20.11 | Port: 22
Description: SSH to internal jump host via port 2222

Navigate: Firewall > NAT > Outbound
Mode: Hybrid Outbound NAT
# Add rule for DMZ servers to use a dedicated public IP
Interface: WAN | Source: 10.10.10.0/24
Translation Address: <dedicated_public_ip>
Description: DMZ outbound NAT via dedicated IP
```

### Step 6: Enable Logging and Monitoring

```
Navigate: Status > System Logs > Settings
  Remote Logging: Enable
  Remote log servers: 10.10.20.15:514 (Syslog/SIEM)
  Log firewall default blocks: Enabled

Navigate: Firewall > Rules
  Enable logging on critical rules:
  - All BLOCK rules
  - WAN inbound PASS rules
  - Inter-VLAN PASS rules

Navigate: Diagnostics > pfTop
  Monitor real-time connection states and bandwidth usage

Install pfBlockerNG package:
  Navigate: System > Package Manager > Available Packages
  Install pfBlockerNG-devel
  Configure IP blocklists (Spamhaus DROP, Emerging Threats)
  Configure DNSBL for malware domain blocking
```

### Step 7: Backup and Test Configuration

```bash
# Export configuration backup
Navigate: Diagnostics > Backup & Restore
Download XML configuration file

# Test rules from each zone
# From LAN:
curl -I https://10.10.20.10  # Should succeed (LAN to SERVERS)
curl -I https://10.10.40.5   # Should fail (LAN to IOT blocked)

# From GUEST:
curl -I https://www.google.com  # Should succeed (internet)
curl -I https://10.10.20.10     # Should fail (guest to internal blocked)

# From DMZ:
nslookup google.com 10.10.20.10  # Should succeed (DNS allowed)
ssh 10.10.1.50                    # Should fail (DMZ to LAN blocked)

# Verify logging
Navigate: Status > System Logs > Firewall
Check that blocked and passed traffic is logging correctly

# Schedule automated config backups
Navigate: Diagnostics > AutoConfigBackup
Enable automatic backups to Netgate cloud or local storage
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Stateful Firewall** | Firewall that tracks the state of network connections and automatically allows return traffic for established sessions without explicit rules |
| **Alias** | Named group of IP addresses, networks, or ports in pfSense that simplifies rule management and improves readability |
| **NAT (Network Address Translation)** | Translation of IP addresses between internal and external networks, including port forwarding for inbound access to internal services |
| **Floating Rules** | pfSense rules that apply across multiple interfaces simultaneously, processed before per-interface rules |
| **pfBlockerNG** | pfSense package that integrates IP reputation blocklists and DNS-based blocklists for automated threat blocking |
| **Rule Processing Order** | pfSense evaluates rules top-to-bottom within each interface tab; first match wins, and unmatched traffic is blocked by default |

## Tools & Systems

- **pfSense 2.7+**: Open-source firewall and router platform based on FreeBSD with web-based management and extensive package ecosystem
- **pfBlockerNG**: IP and DNS blocklist package for automated threat intelligence integration
- **Snort/Suricata packages**: IDS/IPS integration available as pfSense packages for inline traffic inspection
- **OpenVPN/IPsec**: Built-in VPN implementations for site-to-site and remote access connectivity
- **Netgate AutoConfigBackup**: Cloud-based configuration backup service for pfSense disaster recovery

## Common Scenarios

### Scenario: Segmenting a Small Business Network with pfSense

**Context**: A medical practice needs to segment its network to meet HIPAA requirements. They have a single internet connection, an electronic health records (EHR) server, staff workstations, a guest WiFi network, and medical IoT devices (vitals monitors, imaging equipment). Budget constraints require an open-source solution.

**Approach**:
1. Deploy pfSense on a Netgate 4100 appliance with four physical interfaces (WAN, LAN, DMZ, MGMT)
2. Create VLANs for staff (VLAN 10), EHR servers (VLAN 20), guest WiFi (VLAN 30), and medical devices (VLAN 40)
3. Configure strict rules: staff VLAN can access EHR servers on HTTPS only; medical devices can communicate only with the EHR server on specific ports; guest WiFi gets internet-only access with no internal routing
4. Enable pfBlockerNG with healthcare-specific threat feeds and malware domain blocking
5. Configure outbound NAT to prevent internal IP addresses from leaking to the internet
6. Enable comprehensive logging and forward all firewall logs to a SIEM via syslog
7. Set up automated configuration backups and document the rule base for audit compliance

**Pitfalls**:
- Creating rules that are too permissive ("allow any any") instead of specific port-based rules
- Forgetting the rule processing order -- placing a broad PASS rule above a specific BLOCK rule
- Not enabling logging on critical rules, making incident investigation impossible
- Allowing IoT devices unrestricted internet access, creating potential data exfiltration paths

## Output Format

```
## pfSense Firewall Configuration Report

**Device**: pfSense 2.7.2 on Netgate 4100
**Interfaces**: WAN (igb0), LAN (igb1), DMZ (igb2), MGMT (igb3)
**VLANs**: 4 configured (Staff, Servers, Guest, IoT)
**Total Rules**: 28 active rules across all interfaces

### Rule Summary by Interface

| Interface | Pass Rules | Block Rules | Logging Enabled |
|-----------|-----------|-------------|-----------------|
| WAN | 2 | 1 (default) | Yes |
| LAN | 4 | 2 | Yes (blocks) |
| DMZ | 3 | 1 (default) | Yes |
| GUEST | 1 | 2 | Yes |
| IOT | 1 | 3 | Yes |

### Security Controls
- pfBlockerNG: 12 IP blocklists + DNSBL enabled
- Snort IDS: Running on WAN and LAN interfaces
- VPN: OpenVPN remote access configured with MFA
- Logging: All traffic forwarded to SIEM (10.10.20.15)
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
