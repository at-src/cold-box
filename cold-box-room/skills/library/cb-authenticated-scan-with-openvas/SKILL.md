---
name: cb-authenticated-scan-with-openvas
skill_id: cb-authenticated-scan-with-openvas
journal_id: CB-SKL-131
description: Cold-box analyst playbook — Authenticated Scan With Openvas. Configure
  and execute authenticated vulnerability scans using OpenVAS/Greenbone Vulnerability
  Management with SSH and SMB credentials for comprehensive host-level assessment.
domain: cold-box
subdomain: vulnerability-management
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- openvas
- gvm
- authenticated-scan
- vulnerability-scanning
- greenbone
- network-security
- credentialed-scan
cold_box_version: 2
inspired_by: performing-authenticated-scan-with-openvas
---

# Authenticated Scan With Openvas (cold-box)

> **Journal ID:** `CB-SKL-131` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-131`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-authenticated-scan-with-openvas")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-authenticated-scan-with-openvas")` → note **`CB-SKL-131`**
2. `log_skill(case_id, journal_id="CB-SKL-131", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-131` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing authenticated scan with openvas
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sort` | `SIFT-020` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-131] sort per playbook step",
  "why": "Executing cb-authenticated-scan-with-openvas \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-131] grep per playbook step",
  "why": "Executing cb-authenticated-scan-with-openvas \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-131] find per playbook step",
  "why": "Executing cb-authenticated-scan-with-openvas \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-131` (`cb-authenticated-scan-with-openvas`)

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

OpenVAS (Open Vulnerability Assessment Scanner) is the scanner component of the Greenbone Vulnerability Management (GVM) framework. Authenticated scans use valid credentials (SSH for Linux, SMB for Windows, ESXi for VMware) to log into target systems, enabling detection of local vulnerabilities, missing patches, and misconfigurations that unauthenticated scans cannot identify. Authenticated scans typically find 10-50x more vulnerabilities than unauthenticated scans.


## When to Use

- When conducting security assessments that involve performing authenticated scan with openvas
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- GVM 22.x+ installed (gvmd, openvas-scanner, gsad, ospd-openvas)
- PostgreSQL database configured for gvmd
- Redis configured for openvas-scanner
- NVT feed synchronized (greenbone-nvt-sync or greenbone-feed-sync)
- SSH credentials for Linux targets or SMB credentials for Windows targets
- Network access to target hosts on scan ports

## Installation

### Install GVM on Kali Linux / Debian
```bash
# Install GVM package
sudo apt update && sudo apt install -y gvm

# Run initial setup (creates admin account, syncs feeds)
sudo gvm-setup

# Check installation status
sudo gvm-check-setup

# Start all GVM services
sudo gvm-start

# Access Greenbone Security Assistant at https://127.0.0.1:9392
```

### Install via Docker (Recommended for Production)
```bash
# Pull Greenbone Community Edition containers
docker pull greenbone/gvm:stable

# Run with docker-compose
curl -fsSL https://greenbone.github.io/docs/latest/_static/docker-compose-22.4.yml \
  -o docker-compose.yml

# Start the stack
docker compose -f docker-compose.yml -p greenbone-community-edition up -d

# Wait for feed sync (initial sync takes 15-30 minutes)
docker compose -f docker-compose.yml -p greenbone-community-edition \
  logs -f gvmd 2>&1 | grep -i "feed"
```

## Configuring Credentials

### SSH Credentials for Linux Targets
```bash
# Using gvm-cli to create SSH credential with key-based auth
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>Linux SSH Key</name>
    <type>usk</type>
    <login>scan_user</login>
    <key>
      <private><![CDATA['"$(cat /home/scan_user/.ssh/id_rsa)"']]></private>
      <phrase>key_passphrase</phrase>
    </key>
  </create_credential>'

# SSH credential with password authentication
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>Linux SSH Password</name>
    <type>up</type>
    <login>scan_user</login>
    <password>scan_password_here</password>
  </create_credential>'
```

### SMB Credentials for Windows Targets
```bash
# Create SMB credential for Windows authenticated scanning
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>Windows SMB Cred</name>
    <type>up</type>
    <login>DOMAIN\scan_account</login>
    <password>smb_password_here</password>
  </create_credential>'
```

### ESXi Credentials
```bash
# Create ESXi credential for VMware host scanning
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>ESXi Root</name>
    <type>up</type>
    <login>root</login>
    <password>esxi_password_here</password>
  </create_credential>'
```

## Creating Scan Targets

```bash
# Create target with SSH credential (Linux hosts)
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_target>
    <name>Linux Production Servers</name>
    <hosts>192.168.1.10,192.168.1.11,192.168.1.12</hosts>
    <port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/>
    <ssh_credential id="CREDENTIAL_UUID_HERE">
      <port>22</port>
    </ssh_credential>
    <alive_test>ICMP, TCP-ACK Service and ARP Ping</alive_test>
  </create_target>'

# Create target with SMB credential (Windows hosts)
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_target>
    <name>Windows Domain Controllers</name>
    <hosts>192.168.1.20,192.168.1.21</hosts>
    <port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/>
    <smb_credential id="SMB_CREDENTIAL_UUID_HERE"/>
    <alive_test>ICMP, TCP-ACK Service and ARP Ping</alive_test>
  </create_target>'
```

## Scan Configuration

### Built-in Scan Configs
| Config Name | OID | Use Case |
|------------|-----|----------|
| Full and fast | daba56c8-73ec-11df-a475-002264764cea | Standard production scan |
| Full and deep | 708f25c4-7489-11df-8094-002264764cea | Thorough scan, may be disruptive |
| System Discovery | 8715c877-47a0-438d-98a3-27c7a6ab2196 | Host and service enumeration |

### Create Custom Scan Config for Authenticated Scan
```bash
# Clone "Full and fast" config and customize
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_config>
    <copy>daba56c8-73ec-11df-a475-002264764cea</copy>
    <name>Authenticated Full Scan</name>
  </create_config>'
```

## Running the Scan

### Create and Start Scan Task
```bash
# Create scan task
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_task>
    <name>Weekly Authenticated Scan - Linux Prod</name>
    <config id="CONFIG_UUID"/>
    <target id="TARGET_UUID"/>
    <scanner id="08b69003-5fc2-4037-a479-93b440211c73"/>
  </create_task>'

# Start the scan task
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<start_task task_id="TASK_UUID"/>'

# Check scan progress
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_tasks task_id="TASK_UUID"/>'
```

### Schedule Recurring Scans
```bash
# Create weekly schedule (every Sunday at 2:00 AM UTC)
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_schedule>
    <name>Weekly Sunday 2AM</name>
    <icalendar>
BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART:20240101T020000Z
RRULE:FREQ=WEEKLY;BYDAY=SU
DURATION:PT12H
END:VEVENT
END:VCALENDAR
    </icalendar>
    <timezone>UTC</timezone>
  </create_schedule>'
```

## Exporting Results

```bash
# Export scan report as XML
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_reports report_id="REPORT_UUID" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>'

# Export as CSV
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_reports report_id="REPORT_UUID" format_id="c1645568-627a-11e3-a660-406186ea4fc5"/>'

# Use python-gvm for programmatic access
python3 -c "
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

connection = UnixSocketConnection(path='/run/gvmd/gvmd.sock')
transform = EtreeCheckCommandTransform()
with Gmp(connection=connection, transform=transform) as gmp:
    gmp.authenticate('admin', 'password')
    reports = gmp.get_reports()
    print(f'Total reports: {len(reports)}')
"
```

## Validating Authentication Success

```bash
# Check if credentials were accepted during scan
# In the scan report, look for NVT "Authentication tests" results:
# - OID 1.3.6.1.4.1.25623.1.0.103591 (SSH authentication successful)
# - OID 1.3.6.1.4.1.25623.1.0.90023 (SMB authentication successful)

# Verify via gvm-cli
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_results filter="name=SSH rows=10 sort-reverse=severity"/>'
```

## References

- [OpenVAS Official Site](https://www.openvas.org/)
- [Greenbone Community Edition Docs](https://greenbone.github.io/docs/latest/)
- [GVM GitHub Repository](https://github.com/greenbone/openvas-scanner)
- [python-gvm Library](https://github.com/greenbone/python-gvm)
- [GVM Docker Deployment](https://greenbone.github.io/docs/latest/22.4/container/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
