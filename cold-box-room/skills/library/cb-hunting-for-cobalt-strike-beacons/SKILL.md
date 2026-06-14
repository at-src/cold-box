---
name: cb-hunting-for-cobalt-strike-beacons
skill_id: cb-hunting-for-cobalt-strike-beacons
journal_id: CB-SKL-048
description: Cold-box analyst playbook — Hunting For Cobalt Strike Beacons. Detect
  Cobalt Strike beacon network activity using default TLS certificate signatures (serial
  8BB00EE), JA3/JA3S/JARM fingerprints, HTTP C2 profile pattern matching, beacon jitter
  analysis, and named pipe detection via Zeek, Suricata, and P
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- network_pcap
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- cobalt-strike
- beacon
- threat-hunting
- c2
- zeek
- suricata
- ja3
- jarm
- network-forensics
cold_box_version: 2
inspired_by: hunting-for-cobalt-strike-beacons
---

# Hunting For Cobalt Strike Beacons (cold-box)

> **Journal ID:** `CB-SKL-048` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-048`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-cobalt-strike-beacons")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-cobalt-strike-beacons")` → note **`CB-SKL-048`**
2. `log_skill(case_id, journal_id="CB-SKL-048", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-048` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require hunting for cobalt strike beacons
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
  "purpose": "[CB-SKL-048] zeek per playbook step",
  "why": "Executing cb-hunting-for-cobalt-strike-beacons \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-048` (`cb-hunting-for-cobalt-strike-beacons`)

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

Cobalt Strike is the most prevalent command-and-control framework used by both red teams and threat actors. Beacon, its primary payload, communicates with team servers using configurable HTTP/HTTPS/DNS profiles that can mimic legitimate traffic. However, default configurations and behavioral patterns remain detectable through TLS certificate analysis (default serial 8BB00EE), JA3/JA3S fingerprinting, beacon interval jitter analysis, and HTTP malleable profile pattern matching. This skill covers building detection capabilities using Zeek network logs, Suricata IDS rules, and Python-based PCAP analysis to identify beacon callbacks in network traffic.


## When to Use

- When investigating security incidents that require hunting for cobalt strike beacons
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Zeek 6.0+ with JA3 and HASSH packages installed
- Suricata 7.0+ with Emerging Threats ruleset
- Python 3.9+ with scapy and dpkt libraries
- Network traffic captures (PCAP) or live Zeek logs
- RITA (Real Intelligence Threat Analytics) for beacon scoring
- Threat intelligence feeds with known Cobalt Strike IOCs

## Steps

### Step 1: TLS Certificate Analysis
Detect default Cobalt Strike certificates using JA3S fingerprints, certificate serial numbers, and JARM fingerprints in Zeek ssl.log.

### Step 2: Beacon Interval Analysis
Analyze connection timing patterns to identify regular callback intervals with configurable jitter, characteristic of beacon behavior.

### Step 3: HTTP Profile Detection
Match HTTP request patterns (URI paths, headers, user-agents) against known malleable C2 profiles.

### Step 4: Correlate and Score
Combine multiple indicators (TLS + timing + HTTP profile) into a composite beacon confidence score.

## Expected Output

JSON report containing detected beacon candidates with confidence scores, TLS fingerprints, timing analysis, HTTP profile matches, and recommended response actions.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
