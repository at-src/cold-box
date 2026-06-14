---
name: cb-hunting-for-dcsync-attacks
skill_id: cb-hunting-for-dcsync-attacks
journal_id: CB-SKL-232
description: Cold-box analyst playbook — Hunting For Dcsync Attacks. Detect DCSync
  attacks by analyzing Windows Event ID 4662 for unauthorized DS-Replication-Get-Changes
  requests from non-domain-controller accounts.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- general
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- dcsync
- active-directory
- credential-access
- t1003.006
- mimikatz
- windows
- dfir
cold_box_version: 2
inspired_by: hunting-for-dcsync-attacks
---

# Hunting For Dcsync Attacks (cold-box)

> **Journal ID:** `CB-SKL-232` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-232`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-dcsync-attacks")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-dcsync-attacks")` → note **`CB-SKL-232`**
2. `log_skill(case_id, journal_id="CB-SKL-232", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-232` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When hunting for DCSync credential theft (MITRE ATT&CK T1003.006)
- After detecting Mimikatz or similar tools in the environment
- During incident response involving Active Directory compromise
- When monitoring for unauthorized domain replication requests
- During purple team exercises testing AD attack detection

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — procedure steps target external platforms (SIEM, cloud, etc.).
Use for investigation guidance; log `{journal_id}` and note gaps when SIFT cannot run a step.

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

_No SIFT tools mapped for this playbook on cold-box._
Follow the procedure for reasoning; document external-platform gaps in the journal.

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-232` (`cb-hunting-for-dcsync-attacks`)

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

- When hunting for DCSync credential theft (MITRE ATT&CK T1003.006)
- After detecting Mimikatz or similar tools in the environment
- During incident response involving Active Directory compromise
- When monitoring for unauthorized domain replication requests
- During purple team exercises testing AD attack detection

## Prerequisites

- Windows Security Event Log forwarding enabled (Event ID 4662)
- Audit Directory Service Access enabled via Group Policy
- Domain Computers SACL configured on Domain Object for machine account detection
- SIEM with Windows event data ingested (Splunk, Elastic, Sentinel)
- Knowledge of legitimate domain controller accounts and replication partners

## Workflow

1. **Enable Auditing**: Ensure Audit Directory Service Access is enabled on domain controllers.
2. **Collect Events**: Gather Windows Event ID 4662 with AccessMask 0x100 (Control Access).
3. **Filter Replication GUIDs**: Search for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.
4. **Identify Non-DC Sources**: Flag events where SubjectUserName is not a domain controller machine account.
5. **Correlate with Network**: Cross-reference source IPs against known DC addresses.
6. **Validate Findings**: Exclude legitimate replication tools (Azure AD Connect, SCCM).
7. **Respond**: Disable compromised accounts, reset krbtgt, investigate lateral movement.

## Key Concepts

| Concept | Description |
|---------|-------------|
| DCSync | Technique abusing AD replication protocol to extract password hashes |
| Event ID 4662 | Directory Service Access audit event |
| DS-Replication-Get-Changes | GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-All | GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| AccessMask 0x100 | Control Access right indicating extended rights verification |
| T1003.006 | OS Credential Dumping: DCSync |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Windows Event Viewer | Direct event log analysis |
| Splunk | SIEM correlation of Event 4662 |
| Elastic Security | Detection rules for DCSync patterns |
| Mimikatz lsadump::dcsync | Attack tool used to perform DCSync |
| Impacket secretsdump.py | Python-based DCSync implementation |
| BloodHound | Identify accounts with replication rights |

## Output Format

```
Hunt ID: TH-DCSYNC-[DATE]-[SEQ]
Technique: T1003.006
Domain Controller: [DC hostname]
Subject Account: [Account performing replication]
Source IP: [Non-DC IP address]
GUID Accessed: [Replication GUID]
Risk Level: [Critical/High/Medium/Low]
Recommended Action: [Disable account, reset krbtgt, investigate]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
