---
name: cb-ransomware-network-indicators
skill_id: cb-ransomware-network-indicators
journal_id: CB-SKL-316
description: Cold-box analyst playbook — Ransomware Network Indicators. Identify ransomware
  network indicators including C2 beaconing patterns, TOR exit node connections, data
  exfiltration flows, and encryption key exchange via Zeek conn.log and NetFlow analysis
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- malware_analysis
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ransomware
- c2-beaconing
- zeek
- netflow
- tor
- exfiltration
- network-forensics
cold_box_version: 2
inspired_by: analyzing-ransomware-network-indicators
---

# Ransomware Network Indicators (cold-box)

> **Journal ID:** `CB-SKL-316` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-316`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-ransomware-network-indicators")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-ransomware-network-indicators")` → note **`CB-SKL-316`**
2. `log_skill(case_id, journal_id="CB-SKL-316", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-316` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing ransomware network indicators
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `partial` — Tools mapped but some are unavailable — check `describe_sift_tool` / `list_sift_tools`.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `zeek` | `SIFT-119` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-316] zeek per playbook step",
  "why": "Executing cb-ransomware-network-indicators \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-316` (`cb-ransomware-network-indicators`)

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

Before and during ransomware execution, adversaries establish C2 channels, exfiltrate data, and download encryption keys. This skill analyzes Zeek conn.log and NetFlow data to detect beaconing patterns (regular-interval callbacks), connections to known TOR exit nodes, large outbound data transfers, and suspicious DNS activity associated with ransomware families.


## When to Use

- When investigating security incidents that require analyzing ransomware network indicators
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Zeek conn.log files or NetFlow CSV/JSON exports
- Python 3.8+ with standard library
- TOR exit node list (fetched from Tor Project or threat intel feeds)
- Optional: Known ransomware C2 IOC list

## Steps

1. **Parse Connection Logs** — Ingest Zeek conn.log (TSV) or NetFlow records into structured format
2. **Detect Beaconing Patterns** — Calculate connection interval statistics (mean, stddev, coefficient of variation) to identify periodic callbacks
3. **Check TOR Exit Node Connections** — Cross-reference destination IPs against current TOR exit node list
4. **Identify Data Exfiltration** — Flag connections with unusually high outbound byte ratios to external IPs
5. **Analyze DNS Patterns** — Detect DGA-like domain queries and high-entropy subdomains
6. **Score and Correlate** — Apply composite risk scoring across all indicator types
7. **Generate Report** — Produce structured report with timeline and MITRE ATT&CK mapping

## Expected Output

- JSON report with beaconing detections and interval statistics
- TOR exit node connection alerts
- Data exfiltration flow analysis
- Composite ransomware risk score with MITRE mapping (T1071, T1573, T1041)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
