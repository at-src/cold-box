---
name: cb-detecting-golden-ticket-attacks-in-kerberos-logs
skill_id: cb-detecting-golden-ticket-attacks-in-kerberos-logs
journal_id: CB-SKL-024
description: Cold-box analyst playbook — Detecting Golden Ticket Attacks In Kerberos
  Logs. Detect Golden Ticket attacks in Active Directory by analyzing Kerberos TGT
  anomalies including mismatched encryption types, impossible ticket lifetimes, non-existent
  accounts, and forged PAC signatures in domain controller event logs.
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- golden-ticket
- kerberos
- active-directory
- mitre-t1558-001
- credential-abuse
cold_box_version: 2
inspired_by: detecting-golden-ticket-attacks-in-kerberos-logs
---

# Detecting Golden Ticket Attacks In Kerberos Logs (cold-box)

> **Journal ID:** `CB-SKL-024` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-024`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-golden-ticket-attacks-in-kerberos-logs")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-golden-ticket-attacks-in-kerberos-logs")` → note **`CB-SKL-024`**
2. `log_skill(case_id, journal_id="CB-SKL-024", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-024` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When KRBTGT account hash may have been compromised via DCSync or NTDS.dit extraction
- When hunting for forged Kerberos tickets used for persistent domain access
- After incident response reveals credential theft at the domain level
- When investigating impossible logon patterns (users logging in from multiple locations simultaneously)
- During post-breach assessment to determine if Golden Tickets are in use

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sort` | `SIFT-020` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-024] sort per playbook step",
  "why": "Executing cb-detecting-golden-ticket-attacks-in-kerberos-logs \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-024` (`cb-detecting-golden-ticket-attacks-in-kerberos-logs`)

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

- When KRBTGT account hash may have been compromised via DCSync or NTDS.dit extraction
- When hunting for forged Kerberos tickets used for persistent domain access
- After incident response reveals credential theft at the domain level
- When investigating impossible logon patterns (users logging in from multiple locations simultaneously)
- During post-breach assessment to determine if Golden Tickets are in use

## Prerequisites

- Windows Security Event IDs 4768, 4769, 4771 on domain controllers
- Kerberos policy configuration knowledge (max ticket lifetime, encryption types)
- Domain controller audit policy enabling Kerberos Service Ticket Operations
- SIEM with ability to correlate Kerberos events across multiple DCs

## Workflow

1. **Monitor TGT Requests (Event 4768)**: Track Kerberos authentication service requests. Golden Tickets bypass the AS-REQ/AS-REP exchange entirely, so the absence of 4768 before 4769 is suspicious.
2. **Detect Encryption Type Anomalies**: Golden Tickets often use RC4 (0x17) encryption. If your domain enforces AES (0x12), any RC4 TGT is a red flag. Monitor TicketEncryptionType in Event 4769.
3. **Check Ticket Lifetime Anomalies**: Default Kerberos TGT lifetime is 10 hours with 7-day renewal. Golden Tickets can be forged with 10-year lifetimes. Detect tickets with durations exceeding policy.
4. **Hunt for Non-Existent SIDs**: Golden Tickets can include arbitrary SIDs (including non-existent accounts or groups). Correlate TGS requests against known AD SID inventory.
5. **Detect TGS Without Prior TGT**: When a service ticket (4769) appears without a preceding TGT request (4768) from the same IP/account, this may indicate a pre-existing Golden Ticket.
6. **Monitor KRBTGT Password Age**: Track when KRBTGT was last reset. If KRBTGT hash hasn't changed since a known compromise, Golden Tickets from that period remain valid.
7. **Validate PAC Signatures**: With KB5008380+ and PAC validation enforcement, domain controllers reject forged PACs. Monitor for Kerberos failures indicating PAC validation errors.

## Detection Queries

### Splunk -- RC4 Encryption in Kerberos TGS
```spl
index=wineventlog EventCode=4769
| where TicketEncryptionType="0x17"
| where ServiceName!="krbtgt"
| stats count by TargetUserName ServiceName IpAddress TicketEncryptionType Computer
| where count > 5
| sort -count
```

### Splunk -- TGS Without Prior TGT
```spl
index=wineventlog (EventCode=4768 OR EventCode=4769)
| stats earliest(_time) as first_tgt by TargetUserName IpAddress EventCode
| eventstats earliest(eval(if(EventCode=4768, first_tgt, null()))) as tgt_time by TargetUserName IpAddress
| where EventCode=4769 AND (isnull(tgt_time) OR first_tgt < tgt_time)
| table TargetUserName IpAddress first_tgt tgt_time
```

### KQL -- Golden Ticket Indicators
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName != "krbtgt"
| summarize Count=count() by TargetUserName, IpAddress, ServiceName
| where Count > 5
```

## Common Scenarios

1. **Post-DCSync Golden Ticket**: After extracting KRBTGT hash, attacker forges TGT with Domain Admin SID, valid for months until KRBTGT is rotated twice.
2. **RC4 Downgrade**: Golden Ticket forged with RC4 encryption in an AES-only environment, detectable by encryption type mismatch.
3. **Cross-Domain Golden Ticket**: Forged inter-realm TGT used to pivot between AD domains/forests.
4. **Persistence After Remediation**: Golden Tickets surviving password resets because KRBTGT was only rotated once (both current and previous hashes are valid).

## Output Format

```
Hunt ID: TH-GOLDEN-[DATE]-[SEQ]
Suspected Account: [Account using forged ticket]
Source IP: [Client IP]
Target Service: [SPN accessed]
Encryption Type: [RC4/AES128/AES256]
Anomaly: [No prior TGT/RC4 in AES environment/Extended lifetime]
KRBTGT Last Reset: [Date]
Risk Level: [Critical]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
