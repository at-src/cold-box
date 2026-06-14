---
name: cb-detecting-lateral-movement-with-zeek
skill_id: cb-detecting-lateral-movement-with-zeek
journal_id: CB-SKL-196
description: 'Cold-box analyst playbook — Detecting Lateral Movement With Zeek. Detect
  lateral movement in network traffic using Zeek (formerly Bro) log analysis. Parses
  conn.log, smb_mapping.log, smb_files.log, dce_rpc.log, kerberos.log, and ntlm.log
  to identify SMB file transfers, NTLM account spray activity, remote '
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
- zeek
- lateral-movement
- smb
- dce-rpc
- ntlm-spray
- network-forensics
cold_box_version: 2
inspired_by: detecting-lateral-movement-with-zeek
---

# Detecting Lateral Movement With Zeek (cold-box)

> **Journal ID:** `CB-SKL-196` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-196`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-lateral-movement-with-zeek")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-lateral-movement-with-zeek")` → note **`CB-SKL-196`**
2. `log_skill(case_id, journal_id="CB-SKL-196", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-196` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Hunting for lateral movement after an initial compromise indicator is found on one endpoint
- Investigating suspected NTLM account spray or Pass-the-Ticket attacks across the internal network
- Monitoring SMB traffic for unauthorized file transfers to admin shares (C$, ADMIN$, IPC$)
- Detecting remote service execution via DCE/RPC (PsExec, schtasks, WMI lateral patterns)
- Building alerting rules for internal network anomalies in a Zeek-based NSMP deployment
- Performing post-incident timeline reconstruction using Zeek logs as a network-level evidence source

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `head` | `SIFT-011` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `zeek` | `SIFT-119` | no | no |
| `file` | `SIFT-008` | yes | yes |
| `awk` | `SIFT-005` | yes | yes |
| `cut` | `SIFT-006` | yes | yes |
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] head per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] sort per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] grep per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] zeek per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] file per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `awk` → `SIFT-005`

```json
{
  "tool_id": "SIFT-005",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] awk per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `cut` → `SIFT-006`

```json
{
  "tool_id": "SIFT-006",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] cut per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `ls` → `SIFT-014`

```json
{
  "tool_id": "SIFT-014",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-196] ls per playbook step",
  "why": "Executing cb-detecting-lateral-movement-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-196` (`cb-detecting-lateral-movement-with-zeek`)

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

Analyze Zeek network logs to identify lateral movement techniques including
SMB admin share access, DCE/RPC remote service creation, NTLM account spray,
Kerberos ticket anomalies, and large internal data transfers indicative
of staging or exfiltration between hosts.

## When to Use

- Hunting for lateral movement after an initial compromise indicator is found on one endpoint
- Investigating suspected NTLM account spray or Pass-the-Ticket attacks across the internal network
- Monitoring SMB traffic for unauthorized file transfers to admin shares (C$, ADMIN$, IPC$)
- Detecting remote service execution via DCE/RPC (PsExec, schtasks, WMI lateral patterns)
- Building alerting rules for internal network anomalies in a Zeek-based NSMP deployment
- Performing post-incident timeline reconstruction using Zeek logs as a network-level evidence source

**Do not use** as a standalone detection mechanism. Zeek sees network traffic only; combine with endpoint telemetry (Sysmon, EDR) for full visibility. Encrypted SMB3 traffic may limit Zeek's visibility into file-level details.

## Prerequisites

- Zeek 6.0+ deployed on a network tap or SPAN port monitoring internal VLAN traffic
- Zeek SMB analyzer enabled (loaded by default: `@load base/protocols/smb`)
- Zeek DCE/RPC analyzer enabled (`@load base/protocols/dce-rpc`)
- Zeek Kerberos analyzer enabled (`@load base/protocols/krb`)
- Python 3.8+ (standard library only)
- Access to Zeek log directory (default: `/opt/zeek/logs/current/`)
- Familiarity with Zeek TSV log format (fields separated by `\t`, header lines prefixed with `#`)

## Workflow

### Step 1: Verify Zeek Log Collection

Confirm that Zeek is producing the required log files for lateral movement detection:

```bash
# Check that all required analyzers are producing logs
ls -la /opt/zeek/logs/current/conn.log
ls -la /opt/zeek/logs/current/smb_mapping.log
ls -la /opt/zeek/logs/current/smb_files.log
ls -la /opt/zeek/logs/current/dce_rpc.log
ls -la /opt/zeek/logs/current/kerberos.log
ls -la /opt/zeek/logs/current/ntlm.log

# Quick field check on conn.log
zeek-cut id.orig_h id.resp_h id.resp_p proto service < /opt/zeek/logs/current/conn.log | head -20
```

### Step 2: Parse conn.log for Internal Lateral Patterns

Identify connections between internal hosts on lateral-movement-associated ports:

```bash
# Extract SMB connections (port 445) between internal hosts
zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes \
  < /opt/zeek/logs/current/conn.log \
  | awk '$5 == 445 && $7 == "smb"'

# Extract DCE/RPC connections (port 135)
zeek-cut ts id.orig_h id.resp_h id.resp_p service \
  < /opt/zeek/logs/current/conn.log \
  | awk '$4 == 135'

# Extract WinRM connections (port 5985/5986)
zeek-cut ts id.orig_h id.resp_h id.resp_p service \
  < /opt/zeek/logs/current/conn.log \
  | awk '$4 == 5985 || $4 == 5986'
```

### Step 3: Analyze SMB Admin Share Access

Detect access to administrative shares (C$, ADMIN$, IPC$) which is the primary vector for tools like PsExec:

```bash
# Check smb_mapping.log for admin share access
zeek-cut ts id.orig_h id.resp_h path share_type \
  < /opt/zeek/logs/current/smb_mapping.log \
  | grep -iE '(C\$|ADMIN\$|IPC\$)'

# Check smb_files.log for file writes to admin shares
zeek-cut ts id.orig_h id.resp_h action path name size \
  < /opt/zeek/logs/current/smb_files.log \
  | grep -i 'SMB::FILE_WRITE'
```

Deploy the following Zeek script to generate `notice.log` alerts on admin share access:

```zeek
@load base/protocols/smb
@load base/frameworks/notice

redef enum Notice::Type += {
    Admin_Share_Access
};

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) {
    if ( /\$/ in path )
        NOTICE([$note=Admin_Share_Access,
                $msg=fmt("Admin share access: %s -> %s (%s)", c$id$orig_h, c$id$resp_h, path),
                $conn=c]);
}
```

### Step 4: Detect DCE/RPC Remote Service Operations

Monitor for remote service creation and scheduled task registration via DCE/RPC:

```bash
# Look for service control manager operations (PsExec pattern)
zeek-cut ts id.orig_h id.resp_h endpoint operation \
  < /opt/zeek/logs/current/dce_rpc.log \
  | grep -iE '(svcctl|atsvc|ITaskSchedulerService)'
```

### Step 5: Detect NTLM Account Spray

Analyze ntlm.log for authentication anomalies indicating credential reuse.
Zeek's ntlm.log does not expose password hashes, so this detection identifies
a single account authenticating to many hosts in a short window — the network
signature of credential spraying tools like CrackMapExec:

```bash
# Extract NTLM authentications
zeek-cut ts id.orig_h id.resp_h username domainname server_nb_computer_name success \
  < /opt/zeek/logs/current/ntlm.log

# Failed NTLM authentications (brute force or credential testing)
zeek-cut ts id.orig_h id.resp_h username success \
  < /opt/zeek/logs/current/ntlm.log \
  | awk '$5 == "F"'

# Sort by timestamp for timeline analysis
zeek-cut ts id.orig_h id.resp_h username success \
  < /opt/zeek/logs/current/ntlm.log \
  | sort -k1,1
```

Deploy the following Zeek script to generate `notice.log` alerts when a single
account touches more hosts than the threshold in a rolling window:

```zeek
@load base/protocols/ntlm
@load base/frameworks/notice

redef enum Notice::Type += {
    NTLM_Account_Spray
};

global ntlm_tracker: table[string] of set[addr] &create_expire=5min;
const spray_threshold = 3 &redef;

event ntlm_log(rec: NTLM::Info) {
    if ( ! rec?$username || rec$username == "-" )
        return;
    if ( rec$username !in ntlm_tracker )
        ntlm_tracker[rec$username] = set();
    add ntlm_tracker[rec$username][rec$id$resp_h];
    if ( |ntlm_tracker[rec$username]| >= spray_threshold )
        NOTICE([$note=NTLM_Account_Spray,
                $msg=fmt("NTLM account spray: %s -> %d hosts", rec$username, |ntlm_tracker[rec$username]|),
                $sub=rec$username,
                $conn=rec$id]);
}
```

### Step 6: Run the Automated Analysis Agent

Use the provided agent.py for comprehensive lateral movement detection:

```bash
python3 agent.py /opt/zeek/logs/current/
python3 agent.py /opt/zeek/logs/2026-03-18/  # Analyze a specific date
```

## Verification

- Confirm conn.log captures internal SMB (port 445) and DCE/RPC (port 135) connections with correct field parsing
- Verify smb_mapping.log correctly logs admin share paths (C$, ADMIN$, IPC$)
- Test with a known PsExec execution in a lab: expect to see SMB FILE_WRITE of the service binary followed by DCE/RPC svcctl CreateService
- Validate NTLM log parsing by performing a test authentication and confirming username, domain, and success fields are captured; verify the NTLM Account Spray Zeek script generates a `notice.log` entry when the spray threshold is exceeded
- Cross-reference Zeek alerts with Sysmon Event ID 1 (Process Creation) on the target host to confirm end-to-end detection
- Verify the agent correctly handles both TSV and JSON Zeek log formats

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
