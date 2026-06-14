---
name: cb-hunting-advanced-persistent-threats
skill_id: cb-hunting-advanced-persistent-threats
journal_id: CB-SKL-226
description: Cold-box analyst playbook — Hunting Advanced Persistent Threats. Proactively
  hunts for Advanced Persistent Threat (APT) activity within enterprise environments
  using hypothesis-driven searches across endpoint telemetry, network logs, and memory
  artifacts. Use when conducting scheduled threat hunting cycl
domain: cold-box
subdomain: threat-intelligence
tier: adjacent
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- MITRE-ATT&CK
- threat-hunting
- APT
- Velociraptor
- osquery
- Zeek
- TTP
- NIST-CSF
- EDR
cold_box_version: 2
inspired_by: hunting-advanced-persistent-threats
---

# Hunting Advanced Persistent Threats (cold-box)

> **Journal ID:** `CB-SKL-226` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-226`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-advanced-persistent-threats")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-advanced-persistent-threats")` → note **`CB-SKL-226`**
2. `log_skill(case_id, journal_id="CB-SKL-226", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-226` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Conducting proactive threat hunting sprints (typically 2–4 week cycles) based on newly published APT intelligence
- A UEBA alert or anomaly detection system flags behavioral deviations warranting deeper investigation
- A peer organization or ISAC sharing partner reports active APT compromise and you need to validate your own exposure

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `pslist` | `SIFT-182` | no | no |
| `zeek` | `SIFT-119` | no | no |
| `find` | `SIFT-009` | yes | yes |
| `yara` | `SIFT-045` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-226] powershell per playbook step",
  "why": "Executing cb-hunting-advanced-persistent-threats \u2014 see Procedure section",
  "extra_args": []
}
```

### `pslist` → `SIFT-182`

```json
{
  "tool_id": "SIFT-182",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-226] pslist per playbook step",
  "why": "Executing cb-hunting-advanced-persistent-threats \u2014 see Procedure section",
  "extra_args": []
}
```

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-226] zeek per playbook step",
  "why": "Executing cb-hunting-advanced-persistent-threats \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-226] find per playbook step",
  "why": "Executing cb-hunting-advanced-persistent-threats \u2014 see Procedure section",
  "extra_args": []
}
```

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-226] yara per playbook step",
  "why": "Executing cb-hunting-advanced-persistent-threats \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-226` (`cb-hunting-advanced-persistent-threats`)

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
- Conducting proactive threat hunting sprints (typically 2–4 week cycles) based on newly published APT intelligence
- A UEBA alert or anomaly detection system flags behavioral deviations warranting deeper investigation
- A peer organization or ISAC sharing partner reports active APT compromise and you need to validate your own exposure

**Do not use** this skill as a substitute for incident response when a confirmed breach is in progress — escalate to IR procedures (NIST SP 800-61).

## Prerequisites

- EDR platform with telemetry retention (CrowdStrike Falcon, Microsoft Defender for Endpoint, or SentinelOne) covering 30+ days
- Access to MITRE ATT&CK Navigator for hypothesis development
- Network flow data (NetFlow, Zeek, or Suricata logs) in a queryable SIEM
- Threat hunting platform or query interface (Velociraptor, osquery fleet, or Splunk ES)

## Workflow

### Step 1: Develop Hunt Hypothesis

Select a threat actor relevant to your sector using MITRE ATT&CK Groups (https://attack.mitre.org/groups/). Review the group's known TTPs mapped to ATT&CK techniques. Example hypothesis: "APT29 (Cozy Bear) uses spearphishing with ISO attachments (T1566.001) and living-off-the-land binaries (T1218) — test for unusual mshta.exe and rundll32.exe parent-child relationships."

Document hypothesis using the Threat Hunting Loop framework: hypothesis → data collection → pattern analysis → response.

### Step 2: Identify Required Data Sources

Map each ATT&CK technique to required log sources using the ATT&CK Data Sources taxonomy:
- Process creation (T1059): Windows Security Event 4688 or Sysmon Event ID 1
- Network connections (T1071): Zeek conn.log, NetFlow, EDR network telemetry
- Registry modifications (T1547): Sysmon Event ID 13, Windows Security 4657
- Memory injection (T1055): EDR memory scan telemetry, Volatility output

Verify log coverage using ATT&CK Coverage Calculator or a custom data source matrix.

### Step 3: Execute Hunts with Velociraptor or osquery

**Velociraptor VQL hunt** for unusual PowerShell execution:
```vql
SELECT Pid, Ppid, Name, CommandLine, CreateTime
FROM pslist()
WHERE Name =~ "powershell.exe"
AND CommandLine =~ "-enc|-nop|-w hidden"
```

**osquery** for persistence via scheduled tasks:
```sql
SELECT name, action, enabled, path
FROM scheduled_tasks
WHERE action NOT LIKE '%System32%'
AND enabled = 1;
```

**Splunk SPL** for lateral movement via PsExec:
```spl
index=windows EventCode=7045 ServiceFileName="*PSEXESVC*"
| stats count by ComputerName, ServiceName, ServiceFileName
```

### Step 4: Analyze Results and Pivot

For each anomaly identified, pivot across dimensions:
- Temporal: Did this occur before or after known IOC timestamps?
- Host: How many endpoints exhibit this behavior?
- User: Is the associated account a service account, privileged user, or regular user?
- Network: Does the host communicate with external IPs not in baseline?

Apply the Diamond Model (adversary, capability, infrastructure, victim) to structure findings.

### Step 5: Document and Operationalize Findings

If hunting reveals confirmed malicious activity, activate IR procedures. If hunting reveals a gap (hunt found nothing but data coverage was insufficient), document the coverage gap and remediate.

Convert successful hunt queries into SIEM detection rules using Sigma format for portability across platforms.

## Key Concepts

| Term | Definition |
|------|-----------|
| **TTP** | Tactics, Techniques, and Procedures — adversary behavioral patterns as defined in MITRE ATT&CK |
| **Diamond Model** | Analytical framework with four vertices (adversary, capability, infrastructure, victim) used to structure intrusion analysis |
| **Living-off-the-Land (LotL)** | Attacker technique using legitimate OS tools (PowerShell, WMI, certutil) to evade detection |
| **UEBA** | User and Entity Behavior Analytics — ML-based detection of anomalous behavior baselines |
| **Sigma** | Open standard for SIEM-agnostic detection rule format, analogous to YARA for network/log detection |
| **Hunt Hypothesis** | A testable prediction about adversary presence based on threat intelligence and environmental knowledge |

## Tools & Systems

- **Velociraptor**: Open-source DFIR platform with VQL query language for scalable endpoint hunting across thousands of systems
- **osquery**: SQL-based OS instrumentation framework for real-time endpoint telemetry queries
- **MITRE ATT&CK Navigator**: Web-based tool for visualizing ATT&CK coverage and technique prioritization
- **Zeek (formerly Bro)**: Network traffic analyzer producing structured logs (conn, dns, http, ssl) suitable for hunting
- **Elastic Security**: EQL (Event Query Language) enables sequence-based hunting for multi-stage attack patterns
- **Sigma**: Detection rule format with translators for Splunk, QRadar, Sentinel, and Elastic

## Common Pitfalls

- **Confirmation bias**: Starting a hunt expecting to find something and interpreting benign data as malicious. Document null results — they validate controls.
- **Insufficient data retention**: Many APT techniques require 90+ days of log history to identify slow-and-low patterns. Default retention periods are often too short.
- **Hunting without baselines**: Cannot identify anomalies without knowing normal. Spend time on baseline documentation before hunting.
- **Query performance impact**: Broad queries against production SIEM during business hours can degrade analyst workflows. Schedule intensive hunts during off-peak hours.
- **Ignoring false positives systematically**: Track false positive rates per query. Queries with >80% FP rate should be refined or retired before operationalization.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
