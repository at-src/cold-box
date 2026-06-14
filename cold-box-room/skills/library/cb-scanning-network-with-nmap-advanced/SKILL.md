---
name: cb-scanning-network-with-nmap-advanced
skill_id: cb-scanning-network-with-nmap-advanced
journal_id: CB-SKL-322
description: Cold-box analyst playbook — Scanning Network With Nmap Advanced. Performs
  advanced network reconnaissance using Nmap's scripting engine, timing controls,
  evasion techniques, and output parsing to discover hosts, enumerate services, detect
  vulnerabilities, and fingerprint operating systems across authoriz
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
- nmap
- port-scanning
- service-enumeration
- reconnaissance
cold_box_version: 2
inspired_by: scanning-network-with-nmap-advanced
---

# Scanning Network With Nmap Advanced (cold-box)

> **Journal ID:** `CB-SKL-322` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-322`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-scanning-network-with-nmap-advanced")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-scanning-network-with-nmap-advanced")` → note **`CB-SKL-322`**
2. `log_skill(case_id, journal_id="CB-SKL-322", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-322` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Performing comprehensive asset discovery across large enterprise networks during authorized assessments
- Enumerating service versions and configurations to identify outdated or vulnerable software
- Bypassing firewall rules and IDS during authorized penetration tests using scan evasion techniques
- Scripting automated vulnerability checks using the Nmap Scripting Engine (NSE)
- Generating structured scan output for integration into vulnerability management pipelines

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `strings` | `SIFT-044` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `awk` | `SIFT-005` | yes | yes |
| `sed` | `SIFT-016` | yes | yes |
| `r2` | `SIFT-081` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] strings per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] sort per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] grep per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] find per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] file per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

### `awk` → `SIFT-005`

```json
{
  "tool_id": "SIFT-005",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] awk per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

### `sed` → `SIFT-016`

```json
{
  "tool_id": "SIFT-016",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] sed per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

### `r2` → `SIFT-081`

```json
{
  "tool_id": "SIFT-081",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-322] r2 per playbook step",
  "why": "Executing cb-scanning-network-with-nmap-advanced \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-322` (`cb-scanning-network-with-nmap-advanced`)

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

- Performing comprehensive asset discovery across large enterprise networks during authorized assessments
- Enumerating service versions and configurations to identify outdated or vulnerable software
- Bypassing firewall rules and IDS during authorized penetration tests using scan evasion techniques
- Scripting automated vulnerability checks using the Nmap Scripting Engine (NSE)
- Generating structured scan output for integration into vulnerability management pipelines

**Do not use** against networks without explicit written authorization, on production systems during peak hours without approval, or to perform denial-of-service through aggressive scan timing.

## Prerequisites

- Nmap 7.90+ installed (`nmap --version` to verify)
- Root/sudo privileges for SYN scans, OS detection, and raw packet techniques
- Written authorization specifying in-scope IP ranges and any excluded hosts
- Network access to target ranges (VPN, direct connection, or jump host)
- Familiarity with TCP/IP protocols and common port assignments

## Workflow

### Step 1: Host Discovery with Multiple Probes

Use layered discovery to find live hosts even when ICMP is blocked:

```bash
# ARP discovery for local subnet (most reliable on LAN)
nmap -sn -PR 192.168.1.0/24 -oA discovery_arp

# Combined ICMP + TCP + UDP probes for remote networks
nmap -sn -PE -PP -PS21,22,25,80,443,445,3389,8080 -PU53,161,500 10.0.0.0/16 -oA discovery_combined

# List scan to resolve DNS names without sending packets to targets
nmap -sL 10.0.0.0/24 -oN dns_resolution.txt
```

Consolidate results into a live hosts file:

```bash
grep "Host:" discovery_combined.gnmap | awk '{print $2}' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > live_hosts.txt
```

### Step 2: Port Scanning with Timing and Performance Tuning

```bash
# Full TCP SYN scan with optimized timing
nmap -sS -p- --min-rate 5000 --max-retries 2 -T4 -iL live_hosts.txt -oA full_tcp_scan

# Top 1000 UDP ports with version detection
nmap -sU --top-ports 1000 --version-intensity 0 -T4 -iL live_hosts.txt -oA udp_scan

# Specific port ranges for targeted assessment
nmap -sS -p 1-1024,3306,5432,6379,8080-8090,9200,27017 -iL live_hosts.txt -oA targeted_ports
```

### Step 3: Service Version Detection and OS Fingerprinting

```bash
# Aggressive service detection with version intensity
nmap -sV --version-intensity 5 -sC -O --osscan-guess -p <open_ports> -iL live_hosts.txt -oA service_enum

# Specific service probing for ambiguous ports
nmap -sV --version-all -p 8443 --script ssl-cert,http-title,http-server-header <target> -oN service_detail.txt
```

### Step 4: NSE Vulnerability Scanning

```bash
# Run vulnerability detection scripts
nmap --script vuln -p <open_ports> -iL live_hosts.txt -oA vuln_scan

# Target specific vulnerabilities
nmap --script smb-vuln-ms17-010,smb-vuln-ms08-067 -p 445 -iL live_hosts.txt -oA smb_vulns
nmap --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p 443,8443 -iL live_hosts.txt -oA ssl_vulns

# Brute force default credentials on discovered services
nmap --script http-default-accounts,ftp-anon,ssh-auth-methods -p 21,22,80,8080 -iL live_hosts.txt -oA default_creds
```

### Step 5: Firewall Evasion Techniques

```bash
# Fragment packets to evade simple packet inspection
nmap -sS -f --mtu 24 -p 80,443 <target> -oN fragmented_scan.txt

# Use decoy addresses to obscure scan origin
nmap -sS -D RND:10 -p 80,443 <target> -oN decoy_scan.txt

# Spoof source port as DNS (53) to bypass poorly configured firewalls
nmap -sS --source-port 53 -p 1-1024 <target> -oN spoofed_port_scan.txt

# Idle scan using a zombie host (completely stealthy)
nmap -sI <zombie_host> -p 80,443,445 <target> -oN idle_scan.txt

# Slow scan to evade IDS rate-based detection
nmap -sS -T1 --max-rate 10 -p 1-1024 <target> -oA stealth_scan
```

### Step 6: Output Parsing and Reporting

```bash
# Convert XML output to HTML report
xsltproc full_tcp_scan.xml -o scan_report.html

# Extract open ports per host from grepable output
grep "Ports:" full_tcp_scan.gnmap | awk -F'Ports: ' '{print $1 $2}' > open_ports_summary.txt

# Parse XML with nmap-parse-output for structured data
nmap-parse-output full_tcp_scan.xml hosts-to-port 445

# Import into Metasploit database
msfconsole -q -x "db_import full_tcp_scan.xml; hosts; services; exit"

# Generate CSV for vulnerability management tools
nmap-parse-output full_tcp_scan.xml csv > scan_results.csv
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SYN Scan (-sS)** | Half-open TCP scan that sends SYN packets and analyzes responses without completing the three-way handshake, making it faster and stealthier than connect scans |
| **NSE (Nmap Scripting Engine)** | Lua-based scripting framework built into Nmap that enables vulnerability detection, brute forcing, service discovery, and custom automation |
| **Timing Templates (-T0 to -T5)** | Predefined scan speed profiles ranging from Paranoid (T0) to Insane (T5), controlling probe parallelism, timeout values, and inter-probe delays |
| **Idle Scan (-sI)** | Advanced scan technique that uses a zombie host's IP ID sequence to port scan a target without sending packets from the scanner's own IP address |
| **Version Intensity** | Controls how many probes Nmap sends to determine service versions, ranging from 0 (light) to 9 (all probes), trading speed for accuracy |
| **Grepable Output (-oG)** | Legacy Nmap output format designed for easy parsing with grep, awk, and sed for scripted analysis of scan results |

## Tools & Systems

- **Nmap 7.90+**: Core scanning engine with NSE scripting, OS detection, version probing, and multiple output formats
- **nmap-parse-output**: Community tool for parsing Nmap XML output into structured formats (CSV, JSON, host lists)
- **Ndiff**: Nmap utility for comparing two scan results to identify changes in network state over time
- **Zenmap**: Official Nmap GUI providing visual network topology mapping and scan profile management
- **Metasploit Framework**: Imports Nmap XML output for direct correlation of scan results with exploit modules

## Common Scenarios

### Scenario: Enterprise Network Asset Discovery and Vulnerability Baseline

**Context**: A security team needs to establish a vulnerability baseline for a corporate network spanning 10.0.0.0/8 with approximately 5,000 active hosts. Scanning must complete within a weekend maintenance window with minimal network disruption.

**Approach**:
1. Run layered host discovery using ARP (local subnets), TCP SYN (ports 22,80,443,445,3389), and ICMP echo probes across all /24 subnets
2. Perform a full TCP SYN scan on discovered hosts using `--min-rate 5000` and `-T4` to complete within the window
3. Run service version detection and default NSE scripts on all open ports
4. Execute targeted NSE vulnerability scripts for critical services (SMB, SSL/TLS, HTTP)
5. Parse XML output to generate per-subnet CSV reports and import into the vulnerability management platform
6. Schedule Ndiff comparisons against future scans to track remediation progress

**Pitfalls**:
- Setting `--min-rate` too high on congested network segments causing packet loss and false negatives
- Running `-T5` (Insane) timing on production networks, potentially overwhelming older network devices
- Forgetting to scan UDP ports, missing critical services like SNMP (161), DNS (53), and TFTP (69)
- Not saving output in XML format (`-oX` or `-oA`), losing structured data for downstream tool integration

## Output Format

```
## Nmap Scan Summary

**Scan Profile**: Full TCP + Top 200 UDP + Service Enumeration
**Target Range**: 10.10.0.0/16
**Hosts Discovered**: 347 live hosts
**Scan Duration**: 2h 14m

### Critical Findings

| Host | Port | Service | Version | Vulnerability |
|------|------|---------|---------|---------------|
| 10.10.5.23 | 445/tcp | SMB | Windows Server 2012 R2 | MS17-010 (EternalBlue) |
| 10.10.8.100 | 443/tcp | Apache httpd | 2.4.29 | CVE-2021-41773 (Path Traversal) |
| 10.10.12.5 | 3306/tcp | MySQL | 5.6.24 | CVE-2016-6662 (RCE) |
| 10.10.3.77 | 161/udp | SNMP | v2c | Public community string |

### Recommendations
1. Patch MS17-010 on 10.10.5.23 immediately -- Critical RCE vulnerability
2. Upgrade Apache httpd to 2.4.58+ on 10.10.8.100
3. Upgrade MySQL to 8.0.x on 10.10.12.5 and restrict bind address
4. Change SNMP community strings from "public" on 10.10.3.77
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
