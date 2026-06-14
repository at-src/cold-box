---
name: cb-active-directory-compromise-investigation
skill_id: cb-active-directory-compromise-investigation
journal_id: CB-SKL-001
description: Cold-box analyst playbook — Active Directory Compromise Investigation.
  Investigate Active Directory compromise by analyzing authentication logs, replication
  metadata, Group Policy changes, and Kerberos ticket anomalies to identify attacker
  persistence and lateral movement paths.
domain: cold-box
subdomain: incident-response
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- active-directory
- compromise-investigation
- identity-forensics
- kerberos
- lateral-movement
- dfir
- ntds-dit
- golden-ticket
cold_box_version: 2
inspired_by: performing-active-directory-compromise-investigation
---

# Active Directory Compromise Investigation (cold-box)

> **Journal ID:** `CB-SKL-001` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-001`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-active-directory-compromise-investigation")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-active-directory-compromise-investigation")` → note **`CB-SKL-001`**
2. `log_skill(case_id, journal_id="CB-SKL-001", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-001` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing active directory compromise investigation
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

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
  "purpose": "[CB-SKL-001] file per playbook step",
  "why": "Executing cb-active-directory-compromise-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-001` (`cb-active-directory-compromise-investigation`)

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

Active Directory (AD) compromise investigation is a critical incident response capability that focuses on identifying how attackers gained access to domain services, what persistence mechanisms they established, and the scope of credential compromise. Since 88% of breaches involve compromised credentials (Verizon 2025 DBIR), AD is the primary target for enterprise-wide attacks. Investigators must analyze NTDS.dit database integrity, Kerberos ticket-granting activity, Group Policy modifications, replication metadata, and privileged group membership changes to reconstruct the attack chain and determine full compromise scope.


## When to Use

- When conducting security assessments that involve performing active directory compromise investigation
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Familiarity with incident response concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Investigation Areas

### 1. NTDS.dit Database Analysis

The NTDS.dit file is the core Active Directory credential database containing all password hashes for domain accounts. Attackers commonly exfiltrate this file using tools like ntdsutil, secretsdump.py, or DCSync attacks via Mimikatz.

**Detection indicators:**
- Event ID 4662: Access to directory service objects with replication permissions
- Event ID 4742: Computer account modifications on domain controllers
- Volume Shadow Copy creation on domain controllers (Event ID 8222)
- Unusual ntdsutil.exe or vssadmin.exe execution
- Replication traffic from non-DC sources (DCSync detection)

### 2. Kerberos Attack Detection

**Golden Ticket indicators:**
- TGT tickets with abnormally long lifetimes (default is 10 hours)
- Event ID 4769 with encryption type 0x17 (RC4) instead of AES
- TGT issued without corresponding Event ID 4768 (AS-REQ)
- Kerberos tickets referencing non-existent or disabled accounts

**Silver Ticket indicators:**
- Service tickets without corresponding TGT requests
- Event ID 4769 with unusual service names
- Tickets with forged PAC data

**Kerberoasting indicators:**
- High volume of Event ID 4769 for service accounts
- RC4 encryption requests for accounts that support AES
- Requests from workstations not normally accessing those services

### 3. Group Policy Abuse

- GPO modifications granting new privileges (Event ID 5136)
- Scheduled task deployment via GPO
- Software installation policies added to domain
- Login script modifications
- Registry-based policy changes for persistence

### 4. Privileged Group Enumeration

Track modifications to these critical groups:
- Domain Admins, Enterprise Admins, Schema Admins
- Account Operators, Backup Operators
- DnsAdmins (can execute arbitrary DLLs on DCs)
- Group Policy Creator Owners
- Protected Users group membership changes

### 5. Trust Relationship Analysis

- New forest/domain trusts created (Event ID 4706)
- SID History injection for privilege escalation
- Trust ticket forgery indicators
- Cross-domain authentication anomalies

## Investigation Methodology

### Phase 1: Scoping and Evidence Collection
```
1. Identify potentially compromised domain controllers
2. Collect Security, System, Directory Service event logs
3. Extract AD replication metadata using repadmin
4. Capture ntdsutil snapshots for offline analysis
5. Collect DNS server logs and zone transfer records
6. Export Group Policy Object configurations
7. Document current privileged group memberships
```

### Phase 2: Authentication Log Analysis
```
1. Parse Event ID 4624/4625 for logon patterns
2. Identify pass-the-hash indicators (Event ID 4624 Type 3 with NTLM)
3. Analyze Event ID 4768/4769/4771 for Kerberos anomalies
4. Review Event ID 4776 for NTLM authentication failures
5. Cross-reference logon events with known compromised accounts
6. Map lateral movement paths through authentication chains
```

### Phase 3: Persistence and Backdoor Detection
```
1. Enumerate AdminSDHolder ACL modifications
2. Check for SID History abuse on accounts
3. Verify krbtgt account password age
4. Audit DSRM password configuration
5. Check for skeleton key malware indicators
6. Review AD Certificate Services for rogue certificates
7. Validate DNS records for poisoning
```

### Phase 4: Remediation Planning
```
1. Double-rotate krbtgt password (wait replication between rotations)
2. Reset all compromised account passwords
3. Remove unauthorized privileged group members
4. Revoke rogue certificates if AD CS compromised
5. Rebuild domain controllers from clean media if needed
6. Implement tiered administration model
7. Enable Protected Users group for privileged accounts
```

## Critical Event IDs for AD Investigation

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4662 | Security | Operation on AD object |
| 4768 | Security | Kerberos TGT requested |
| 4769 | Security | Kerberos service ticket requested |
| 4771 | Security | Kerberos pre-authentication failed |
| 4776 | Security | NTLM credential validation |
| 5136 | Security | Directory object modified |
| 5137 | Security | Directory object created |
| 4706 | Security | Trust created |
| 4707 | Security | Trust removed |
| 4742 | Security | Computer account changed |
| 8222 | System | Shadow copy created |

## Tools for AD Investigation

| Tool | Purpose |
|------|---------|
| **BloodHound** | Attack path mapping and privilege escalation analysis |
| **Pingcastle** | AD security assessment and risk scoring |
| **Purple Knight** | AD vulnerability scanning by Semperis |
| **ADRecon** | Active Directory data gathering |
| **Mimikatz** | Credential extraction and Kerberos analysis |
| **Impacket** | DCSync detection and NTLM relay analysis |
| **Velociraptor** | Remote forensic artifact collection |
| **Timeline Explorer** | Event log timeline analysis |

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|-----------|----|-----------|
| DCSync | T1003.006 | NTDS.dit credential extraction |
| Golden Ticket | T1558.001 | Kerberos TGT forgery |
| Silver Ticket | T1558.002 | Service ticket forgery |
| Kerberoasting | T1558.003 | Service account hash extraction |
| Pass-the-Hash | T1550.002 | NTLM hash reuse |
| Group Policy Modification | T1484.001 | Persistence via GPO |
| Account Manipulation | T1098 | Privileged group changes |
| SID-History Injection | T1134.005 | Privilege escalation |

## References

- [CISA: Detecting and Mitigating Active Directory Compromises](https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises)
- [Microsoft: Total Identity Compromise IR Lessons](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/total-identity-compromise-microsoft-incident-response-lessons-on-securing-active/3753391)
- [Semperis: Top 10 Active Directory Risks](https://www.semperis.com/blog/10-ad-risks-caught-by-identity-forensics-and-incident-response/)
- [Fidelis: Active Directory Compromise Response](https://fidelissecurity.com/threatgeek/active-directory-security/respond-after-an-active-directory-compromise/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
