---
name: cb-detecting-dcsync-attack-in-active-directory
skill_id: cb-detecting-dcsync-attack-in-active-directory
journal_id: CB-SKL-181
description: Cold-box analyst playbook — Detecting Dcsync Attack In Active Directory.
  Detect DCSync attacks where adversaries abuse Active Directory replication privileges
  to extract password hashes by monitoring for non-domain-controller accounts requesting
  directory replication via DsGetNCChanges.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- active-directory
- dcsync
- credential-theft
- mitre-t1003-006
- mimikatz
- kerberos
cold_box_version: 2
inspired_by: detecting-dcsync-attack-in-active-directory
---

# Detecting Dcsync Attack In Active Directory (cold-box)

> **Journal ID:** `CB-SKL-181` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-181`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-dcsync-attack-in-active-directory")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-dcsync-attack-in-active-directory")` → note **`CB-SKL-181`**
2. `log_skill(case_id, journal_id="CB-SKL-181", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-181` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for credential theft in Active Directory environments
- After compromise of accounts with Replicating Directory Changes permissions
- When investigating suspected use of Mimikatz or Impacket secretsdump
- During incident response involving lateral movement with domain admin credentials
- When auditing AD replication permissions as part of security hardening

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `sort` | `SIFT-020` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-181] powershell per playbook step",
  "why": "Executing cb-detecting-dcsync-attack-in-active-directory \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-181] sort per playbook step",
  "why": "Executing cb-detecting-dcsync-attack-in-active-directory \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-181` (`cb-detecting-dcsync-attack-in-active-directory`)

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

- When hunting for credential theft in Active Directory environments
- After compromise of accounts with Replicating Directory Changes permissions
- When investigating suspected use of Mimikatz or Impacket secretsdump
- During incident response involving lateral movement with domain admin credentials
- When auditing AD replication permissions as part of security hardening

## Prerequisites

- Windows Security Event Logs with Event ID 4662 (Object Access) enabled
- Advanced Audit Policy: Audit Directory Service Access enabled
- Domain Controller event forwarding to SIEM
- Knowledge of legitimate domain controller hostnames and IPs
- Directory Service Access auditing with SACL on domain object

## Workflow

1. **Identify Legitimate Replication Sources**: Document all domain controllers in the environment by hostname, IP, and computer account. Only these should perform directory replication.
2. **Enable Required Auditing**: Configure Advanced Audit Policy to capture Event ID 4662 on domain controllers with specific GUID monitoring for replication rights.
3. **Monitor Replication Rights Access**: Track access to three critical GUIDs -- DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2), DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2), and DS-Replication-Get-Changes-In-Filtered-Set (89e95b76-444d-4c62-991a-0facbeda640c).
4. **Detect Non-DC Replication Requests**: Alert when any account NOT associated with a domain controller requests replication rights.
5. **Correlate with Network Traffic**: DCSync generates replication traffic (MS-DRSR/RPC) from the attacker's machine to the DC. Monitor for DrsGetNCChanges RPC calls from non-DC IP addresses.
6. **Investigate Source Context**: Examine the process, user account, and machine originating the replication request.
7. **Check for Credential Abuse**: After DCSync detection, audit for subsequent use of extracted hashes (pass-the-hash, golden ticket creation).

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1003.006 | OS Credential Dumping: DCSync |
| DCSync | Mimicking domain controller replication to extract credentials |
| DsGetNCChanges | RPC function used to request AD replication data |
| DS-Replication-Get-Changes | AD permission required (GUID: 1131f6aa-...) |
| DS-Replication-Get-Changes-All | Permission including confidential attributes (GUID: 1131f6ad-...) |
| MS-DRSR | Microsoft Directory Replication Service Remote Protocol |
| KRBTGT Hash | Key target of DCSync enabling Golden Ticket attacks |
| Event ID 4662 | Directory service object access audit event |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Mimikatz (lsadump::dcsync) | Primary DCSync attack tool |
| Impacket secretsdump.py | Python-based DCSync implementation |
| DSInternals | PowerShell module for AD replication |
| BloodHound | Map accounts with replication rights |
| Splunk / Elastic | SIEM correlation of 4662 events |
| Microsoft Defender for Identity | Native DCSync detection |
| CrowdStrike Falcon | EDR-based DCSync detection |

## Detection Queries

### Splunk -- DCSync Detection via Event 4662
```spl
index=wineventlog EventCode=4662
| where Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
    "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
    "*89e95b76-444d-4c62-991a-0facbeda640c*")
| where NOT match(SubjectUserName, ".*\\$$")
| where NOT SubjectUserName IN ("known_svc_account1", "known_svc_account2")
| stats count values(Properties) as ReplicationRights by SubjectUserName SubjectDomainName Computer
| where count > 0
| table SubjectUserName SubjectDomainName Computer count ReplicationRights
```

### KQL -- Microsoft Sentinel DCSync Detection
```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !endswith "$"
| where SubjectUserName !in ("AzureADConnect", "MSOL_*")
| project TimeGenerated, SubjectUserName, SubjectDomainName, Computer, Properties
| sort by TimeGenerated desc
```

### Sigma Rule -- DCSync Activity
```yaml
title: DCSync Activity Detected - Non-DC Replication Request
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter_dc:
        SubjectUserName|endswith: '$'
    condition: selection and not filter_dc
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006
```

## Common Scenarios

1. **Mimikatz DCSync**: Attacker with Domain Admin privileges runs `lsadump::dcsync /user:krbtgt` to extract KRBTGT hash for Golden Ticket creation.
2. **Impacket secretsdump**: Remote DCSync via `secretsdump.py domain/user:password@dc-ip` extracting all domain hashes.
3. **Delegated Replication Rights**: Attacker grants themselves Replicating Directory Changes rights via ACL modification before performing DCSync.
4. **Azure AD Connect Abuse**: Compromising the Azure AD Connect service account which has legitimate replication rights.
5. **DSInternals PowerShell**: Using `Get-ADReplAccount` cmdlet to replicate specific account credentials.

## Output Format

```
Hunt ID: TH-DCSYNC-[DATE]-[SEQ]
Alert Severity: Critical
Source Account: [Account requesting replication]
Source Machine: [Hostname/IP of requestor]
Target DC: [Domain controller receiving request]
Replication Rights: [GUIDs accessed]
Timestamp: [Event time]
Legitimate DC: [Yes/No]
Known Service Account: [Yes/No]
Risk Assessment: [Critical - non-DC replication detected]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
