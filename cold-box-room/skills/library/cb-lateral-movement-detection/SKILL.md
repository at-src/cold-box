---
name: cb-lateral-movement-detection
skill_id: cb-lateral-movement-detection
journal_id: CB-SKL-069
description: Cold-box analyst playbook — Lateral Movement Detection. Detects lateral
  movement techniques including Pass-the-Hash, PsExec, WMI execution, RDP pivoting,
  and SMB-based spreading using SIEM correlation of Windows event logs, network flow
  data, and endpoint telemetry mapped to MITRE ATT&CK Lateral
domain: cold-box
subdomain: soc-operations
tier: core
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- soc
- lateral-movement
- mitre-attack
- pass-the-hash
- psexec
- wmi
- rdp
- smb
- detection
cold_box_version: 2
inspired_by: performing-lateral-movement-detection
---

# Lateral Movement Detection (cold-box)

> **Journal ID:** `CB-SKL-069` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-069`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-lateral-movement-detection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-lateral-movement-detection")` → note **`CB-SKL-069`**
2. `log_skill(case_id, journal_id="CB-SKL-069", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-069` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- SOC teams need to detect attackers pivoting between systems after initial compromise
- Incident investigations require tracking an attacker's movement path through the network
- Detection engineering needs lateral movement rules mapped to ATT&CK TA0008 techniques
- Red/purple team exercises identify lateral movement detection gaps

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `sort` | `SIFT-020` | yes | yes |
| `zeek` | `SIFT-119` | no | no |
| `wmic` | `SIFT-186` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-069] powershell per playbook step",
  "why": "Executing cb-lateral-movement-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-069] sort per playbook step",
  "why": "Executing cb-lateral-movement-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-069] zeek per playbook step",
  "why": "Executing cb-lateral-movement-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `wmic` → `SIFT-186`

```json
{
  "tool_id": "SIFT-186",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-069] wmic per playbook step",
  "why": "Executing cb-lateral-movement-detection \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-069` (`cb-lateral-movement-detection`)

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

Use this skill when:
- SOC teams need to detect attackers pivoting between systems after initial compromise
- Incident investigations require tracking an attacker's movement path through the network
- Detection engineering needs lateral movement rules mapped to ATT&CK TA0008 techniques
- Red/purple team exercises identify lateral movement detection gaps

**Do not use** for detecting initial access or external attacks — lateral movement detection focuses on internal host-to-host pivot activity.

## Prerequisites

- Windows Security Event Logs (EventCode 4624, 4625, 4648, 4672) from all endpoints and servers
- Sysmon deployed with process creation (EventCode 1), network connections (EventCode 3), and named pipe (EventCode 17/18)
- Network flow data (NetFlow/sFlow, Zeek connection logs) for internal traffic analysis
- SIEM with cross-source correlation capability
- Baseline of normal internal authentication patterns

## Workflow

### Step 1: Detect Pass-the-Hash / Pass-the-Ticket (T1550)

**Pass-the-Hash Detection (EventCode 4624 with NTLM):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
AuthenticationPackageName="NTLM"
| where TargetUserName!="ANONYMOUS LOGON" AND TargetUserName!="$"
| stats count, dc(ComputerName) AS unique_targets, values(ComputerName) AS targets
  by src_ip, TargetUserName
| where unique_targets > 3
| eval alert = "Possible Pass-the-Hash: NTLM network logon to ".unique_targets." hosts"
| sort - unique_targets
| table src_ip, TargetUserName, unique_targets, count, targets, alert
```

**Overpass-the-Hash Detection (Kerberos with RC4):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
TicketEncryptionType="0x17"
| where ServiceName!="krbtgt" AND ServiceName!="$"
| stats count, dc(ServiceName) AS unique_services by src_ip, TargetUserName
| where count > 5
| eval alert = "Possible Overpass-the-Hash: RC4 Kerberos tickets from ".src_ip
| table _time, src_ip, TargetUserName, unique_services, count, alert
```

**Golden/Silver Ticket Detection (T1558):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
| where TicketOptions="0x40810000" OR TicketOptions="0x40800000"
| eval ticket_lifetime = TicketExpireTime - TicketIssueTime
| where ticket_lifetime > 36000  --- >10 hours (abnormal)
| stats count by src_ip, TargetUserName, ServiceName, TicketEncryptionType, TicketOptions
| eval alert = "Possible Golden/Silver Ticket: Abnormal ticket properties"
```

### Step 2: Detect Remote Service Exploitation (T1021)

**PsExec Detection (T1021.002):**
```spl
--- Via Sysmon process creation
index=sysmon EventCode=1
(Image="*\\psexec.exe" OR Image="*\\psexesvc.exe"
 OR OriginalFileName="psexec.c" OR OriginalFileName="psexesvc.exe"
 OR ParentImage="*\\psexesvc.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine, Hashes

--- Via named pipe creation (Sysmon EventCode 17)
index=sysmon EventCode=17
PipeName IN ("\\PSEXESVC*", "\\RemCom*", "\\csexec*")
| table _time, Computer, User, Image, PipeName

--- Via Windows service creation (EventCode 7045)
index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
ServiceName="PSEXESVC" OR ServiceFileName="*PSEXESVC*"
| table _time, Computer, ServiceName, ServiceFileName, AccountName
```

**WMI Remote Execution (T1047):**
```spl
index=sysmon EventCode=1
(Image="*\\wmic.exe" AND CommandLine="*/node:*")
OR (ParentImage="*\\WmiPrvSE.exe" AND Image IN ("*\\cmd.exe", "*\\powershell.exe"))
| eval execution_type = case(
    match(Image, "wmic"), "WMI Command Line",
    match(ParentImage, "WmiPrvSE"), "WMI Provider Host (remote execution)"
  )
| table _time, Computer, User, execution_type, ParentImage, Image, CommandLine
```

**WinRM/PowerShell Remoting (T1021.006):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624
Logon_Type=3 AuthenticationPackageName="Kerberos"
| where ProcessName="*\\wsmprovhost.exe" OR ProcessName="*\\powershell.exe"
| stats count, dc(ComputerName) AS unique_targets by src_ip, TargetUserName
| where unique_targets > 2
| eval alert = "PowerShell Remoting to ".unique_targets." hosts from ".src_ip

--- Sysmon variant
index=sysmon EventCode=1
ParentImage="*\\wsmprovhost.exe"
Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\csc.exe")
| table _time, Computer, User, Image, CommandLine
```

**RDP Lateral Movement (T1021.001):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count, dc(ComputerName) AS rdp_targets, values(ComputerName) AS destinations,
        earliest(_time) AS first_rdp, latest(_time) AS last_rdp
  by src_ip, TargetUserName
| where rdp_targets > 2
| eval duration_hours = round((last_rdp - first_rdp) / 3600, 1)
| eval alert = TargetUserName." RDP'd to ".rdp_targets." hosts in ".duration_hours." hours"
| sort - rdp_targets
```

### Step 3: Detect SMB-Based Lateral Movement

**Anomalous SMB Traffic Patterns:**
```spl
index=firewall OR index=zeek sourcetype IN ("pan:traffic", "bro:conn:json")
dest_port=445 action=allowed
| where src_ip!=dest_ip
| stats count AS smb_sessions, dc(dest_ip) AS unique_targets,
        sum(bytes_out) AS total_bytes
  by src_ip
| where unique_targets > 10
| eval alert = case(
    unique_targets > 50, "CRITICAL: Mass SMB enumeration from ".src_ip,
    unique_targets > 20, "HIGH: Significant SMB lateral movement",
    unique_targets > 10, "MEDIUM: Elevated SMB connections"
  )
| sort - unique_targets
```

**Admin Share Access (C$, ADMIN$):**
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=5140
ShareName IN ("\\\\*\\C$", "\\\\*\\ADMIN$", "\\\\*\\IPC$")
| where SubjectUserName!="SYSTEM" AND SubjectUserName!="$"
| stats count, dc(ComputerName) AS unique_hosts by SubjectUserName, ShareName, src_ip
| where unique_hosts > 3
| eval alert = "Admin share access to ".unique_hosts." hosts by ".SubjectUserName
| sort - unique_hosts
```

### Step 4: Build Lateral Movement Graph

Visualize the attack path:

```spl
--- Build source->destination graph for authentication events
index=wineventlog EventCode=4624 Logon_Type IN (3, 10)
earliest=-24h
| stats count AS connections, latest(_time) AS last_connection
  by src_ip, ComputerName, TargetUserName, Logon_Type
| eval edge = src_ip." -> ".ComputerName." (User: ".TargetUserName.", Type: ".Logon_Type.")"
| sort - connections
| table edge, connections, last_connection

--- Network flow correlation
index=netflow earliest=-24h
dest_port IN (445, 135, 3389, 5985, 5986)
| stats sum(bytes) AS total_bytes, count AS flow_count,
        dc(dest_ip) AS targets by src_ip, dest_port
| where targets > 5
| eval service = case(
    dest_port=445, "SMB",
    dest_port=135, "RPC/WMI",
    dest_port=3389, "RDP",
    dest_port IN (5985, 5986), "WinRM"
  )
| sort - targets
| table src_ip, service, targets, flow_count, total_bytes
```

### Step 5: Detect DCOM and Scheduled Task-Based Movement

**DCOM Lateral Execution (T1021.003):**
```spl
index=sysmon EventCode=1
ParentImage IN ("*\\mmc.exe", "*\\excel.exe", "*\\outlook.exe")
Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\mshta.exe")
| where ParentCommandLine="*-Embedding*"
| eval alert = "DCOM-based lateral movement: ".ParentImage." spawned ".Image
| table _time, Computer, User, ParentImage, Image, CommandLine, alert
```

**Remote Scheduled Task Creation (T1053.005):**
```spl
index=wineventlog EventCode=4698
| where SubjectUserName!="SYSTEM"
| eval task_xml = TaskContent
| search task_xml="*http*" OR task_xml="*powershell*" OR task_xml="*cmd*" OR task_xml="*\\Temp\\*"
| table _time, Computer, SubjectUserName, TaskName, task_xml
```

### Step 6: Correlate Movement with Kill Chain Phases

Build end-to-end attack chain detection:

```spl
--- Detect complete lateral movement sequence
index=wineventlog OR index=sysmon
(EventCode=4625 OR EventCode=4624 OR EventCode=1 OR EventCode=4698 OR EventCode=5140)
| eval phase = case(
    EventCode=4625, "1-Recon/BruteForce",
    EventCode=4624 AND Logon_Type=3, "2-Lateral Movement",
    EventCode=5140 AND match(ShareName, "C\$|ADMIN\$"), "3-Admin Share Access",
    EventCode=1 AND match(ParentImage, "psexesvc|WmiPrvSE|wsmprovhost"), "4-Remote Execution",
    EventCode=4698, "5-Persistence (Scheduled Task)",
    1=1, "other"
  )
| where phase!="other"
| stats count by phase, src_ip, ComputerName, TargetUserName
| sort phase, _time
| table phase, src_ip, ComputerName, TargetUserName, count
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Lateral Movement** | Post-compromise technique where attackers pivot between systems to reach targets |
| **Pass-the-Hash** | Using stolen NTLM hash for authentication without knowing the plaintext password |
| **Pass-the-Ticket** | Using stolen Kerberos TGT/TGS tickets for authentication across the domain |
| **PsExec** | Sysinternals tool (and attack technique) for remote process execution via SMB and named pipes |
| **WMI Execution** | Using Windows Management Instrumentation for remote command execution via DCOM or WinRM |
| **Admin Share** | Default Windows administrative shares (C$, ADMIN$, IPC$) used for remote system management |

## Tools & Systems

- **Splunk Enterprise Security**: SIEM platform for correlating Windows events, Sysmon, and network flows
- **Microsoft Defender for Identity**: Cloud service detecting lateral movement via domain controller monitoring
- **BloodHound**: Active Directory attack path analysis tool for identifying lateral movement opportunities
- **CrowdStrike Falcon**: EDR platform with lateral movement detection and automated containment
- **Zeek (Bro)**: Network monitor generating connection logs for SMB, RDP, and WinRM traffic analysis

## Common Scenarios

- **PsExec Spread**: Attacker uses PsExec to execute malware across 20 workstations — detect via service creation events
- **RDP Pivoting**: Compromised VPN account used to RDP through multiple internal hosts — detect via Logon_Type 10 chains
- **WMI Recon and Execution**: Attacker uses WMI for discovery then execution — detect via WmiPrvSE child processes
- **Pass-the-Hash Campaign**: Stolen local admin hash used across subnet — detect via NTLM Logon_Type 3 to multiple hosts
- **Scheduled Task Persistence**: Remote scheduled task created on domain controller — detect via EventCode 4698 from non-admin source

## Output Format

```
LATERAL MOVEMENT DETECTION REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Period:       2024-03-15 14:00 to 18:00 UTC
Source:       192.168.1.105 (WORKSTATION-042)

Movement Path:
  14:23  192.168.1.105 → 10.0.5.20  (DC-PRIMARY) — PtH via NTLM Type 3
  14:25  10.0.5.20 → 10.0.5.21     (DC-BACKUP)  — Kerberos ticket reuse
  14:28  10.0.5.20 → 10.0.10.15    (FILESERVER-01) — PsExec service creation
  14:32  10.0.10.15 → 10.0.10.20   (DB-PRIMARY) — WMI remote execution
  14:35  10.0.10.20 → 10.0.10.25   (DB-BACKUP)  — SMB admin share access

Techniques Detected:
  T1550.002 — Pass-the-Hash (NTLM authentication to DC)
  T1021.002 — PsExec (remote service installation)
  T1047     — WMI Execution (WmiPrvSE child process)
  T1021.002 — SMB Admin Share (C$ access on DB-BACKUP)

Affected Systems: 5 hosts across 2 network segments
User Account:     admin_compromised (Domain Admin)
Containment:      All 5 hosts isolated at 14:45 UTC
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
